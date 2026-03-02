# TEESimulator KeyAttestation 防御完善性分析

## 🎯 核心问题

**蓝方提问：TEESimulator 真的做足了 KeyAttestation 防御，防住了 ChunQiu 的所有进攻性检测吗？**

---

## 📊 完整性评估

### ✅ TEESimulator 已实现的功能

| 功能 | 实现状态 | 关键文件 |
|------|---------|---------|
| 证书链伪造 | ✅ 完善 | AttestationPatcher.kt |
| TEE Enforced 字段伪造 | ✅ 完善 | AttestationBuilder.kt |
| Software Enforced 字段伪造 | ✅ 完善 | AttestationBuilder.kt |
| RootOfTrust 伪造 | ✅ 完善 | AttestationBuilder.kt |
| 设备标识符伪造 | ✅ 完善 | AttestationBuilder.kt |
| 补丁级别伪造 | ✅ 完善 | AndroidDeviceUtils.kt |
| Keybox 管理 | ✅ 完善 | KeyBoxManager.kt |
| 证书链签名 | ✅ 有效 | AttestationPatcher.kt |

### ⚠️ 潜在问题

| 问题 | 严重程度 | 说明 |
|------|---------|------|
| **BootKey/BootHash 来源** | 🔴 高 | 如果系统属性不存在，使用随机值 |
| **Keybox 证书过期** | 🟡 中 | 示例 keybox 证书 2026 年过期 |
| **Module Hash 计算** | 🟡 中 | 依赖 /apex 目录结构 |
| **Attestation Version** | 🟢 低 | 自动匹配设备版本 |

---

## 🔍 详细分析

### 1. BootKey 和 BootHash 问题 🔴

```kotlin
// AndroidDeviceUtils.kt
val bootKey: ByteArray by lazy {
    initializeBootProperty(
        propertyName = "ro.boot.vbmeta.public_key_digest",
        attestationValueProvider = { DeviceAttestationService.CachedAttestationData?.verifiedBootKey },
        expectedSize = 32,
    )
}
```

**问题**：
- 如果 `ro.boot.vbmeta.public_key_digest` 不存在
- 且没有缓存的 TEE attestation 数据
- 则使用**随机生成的值**

**后果**：
- 每次启动可能产生不同的 BootKey/BootHash
- 如果 ChunQiu 缓存了之前的值，会检测到不一致

**解决方案**：
```kotlin
// 确保使用持久化存储
private fun initializeBootProperty(...): ByteArray {
    // 1. 先尝试从持久化存储读取
    val cached = readFromPersistentStorage(propertyName)
    if (cached != null) return cached
    
    // 2. 然后尝试系统属性
    getProperty(propertyName, expectedSize)?.let { 
        saveToPersistentStorage(propertyName, it)
        return it 
    }
    
    // 3. 最后才使用随机值（并持久化）
    return generateRandomBytes(expectedSize).also {
        saveToPersistentStorage(propertyName, it)
    }
}
```

### 2. Keybox 证书链问题 🟡

**当前状态**：
```
证书链结构:
├── Leaf Certificate (中间证书签名)
│   └── Subject: Android Keystore Software Attestation Intermediate
├── Intermediate Certificate (根证书签名)
│   └── Subject: Android Keystore Software Attestation Root
└── Root Certificate (自签名)
    └── Subject: Android Keystore Software Attestation Root
```

**问题**：
- 示例 keybox 使用的是 **"Software Attestation"** 证书
- 真实 TEE 使用的是 **"Hardware Attestation"** 证书
- 证书颁发者应该是 Google Hardware Attestation Root

**检测点**：
```java
// ChunQiu 可能的检测
if (cert.getIssuerDN().contains("Software Attestation")) {
    return DETECTED;  // 软件模拟！
}
```

**解决方案**：
- 使用真实的 Hardware Attestation keybox
- 或确保证书链显示为 Hardware Attestation

### 3. Module Hash 计算问题 🟡

```kotlin
// AndroidDeviceUtils.kt
val moduleHash: ByteArray by lazy {
    DeviceAttestationService.CachedAttestationData?.moduleHash
        ?: runCatching {
            // 从 /apex 目录计算
            apexInfos.map { (packageName, versionCode) -> ... }
        }
}
```

**问题**：
- Module Hash 是从 `/apex` 目录动态计算的
- 如果设备上的 APEX 模块发生变化，hash 会改变
- 需要确保一致性

**检测点**：
```java
// ChunQiu 可能的检测
// 比较多次 attestation 的 moduleHash 是否一致
if (previousHash != null && !previousHash.equals(currentHash)) {
    return SUSPICIOUS;  // Hash 不一致
}
```

### 4. Security Level 报告问题 🟢

```kotlin
// AttestationBuilder.kt
ASN1Enumerated(securityLevel)  // attestationSecurityLevel
ASN1Enumerated(securityLevel)  // keymasterSecurityLevel
```

**当前实现**：正确报告 `TRUSTED_ENVIRONMENT` 或 `STRONGBOX`

**潜在问题**：
- 如果设备实际上没有 TEE 硬件
- 但报告了 `TRUSTED_ENVIRONMENT`
- 可能被其他检测层交叉验证

---

## 🎯 ChunQiu 可能的检测点

### 检测点 1: 证书链验证

```java
// 验证证书链是否有效
// 验证证书是否由 Google Hardware Attestation Root 签发
// 验证证书是否在有效期内
```

**TEESimulator 状态**: ⚠️ 使用的是 Software Attestation 证书

### 检测点 2: Attestation 扩展字段验证

```java
// 验证 attestationVersion 是否与设备匹配
// 验证 attestationSecurityLevel 是否合理
// 验证 keymasterVersion 是否与设备匹配
// 验证 keymasterSecurityLevel 是否合理
```

**TEESimulator 状态**: ✅ 已正确实现

### 检测点 3: RootOfTrust 验证

```java
// 验证 verifiedBootKey 是否与设备一致
// 验证 verifiedBootHash 是否与设备一致
// 验证 verifiedBootState 是否合理
// 验证 deviceLocked 是否与实际状态一致
```

**TEESimulator 状态**: ⚠️ BootKey/BootHash 可能不一致

### 检测点 4: 设备标识符验证

```java
// 验证 brand, device, product 是否与 Build 信息一致
// 验证 serial, IMEI 是否与实际设备一致
// 验证 manufacturer, model 是否与 Build 信息一致
```

**TEESimulator 状态**: ✅ 已正确实现（从 KeyMintAttestation 参数获取）

### 检测点 5: 补丁级别验证

```java
// 验证 osPatchLevel 是否与 Build.VERSION.SECURITY_PATCH 一致
// 验证 vendorPatchLevel 是否与 ro.vendor.build.security_patch 一致
// 验证 bootPatchLevel 是否合理
```

**TEESimulator 状态**: ✅ 已正确实现

### 检测点 6: 时间一致性验证

```java
// 验证 creationDateTime 是否在合理范围内
// 验证证书的 notBefore/notAfter 是否合理
// 验证多次 attestation 的时间是否递增
```

**TEESimulator 状态**: ✅ 已正确实现

### 检测点 7: Module Hash 验证

```java
// 验证 moduleHash 是否与设备的 APEX 模块一致
// 验证多次 attestation 的 moduleHash 是否一致
```

**TEESimulator 状态**: ⚠️ 需要确保一致性

### 检测点 8: Application ID 验证

```java
// 验证 attestationApplicationId 是否与调用应用一致
// 验证 package signature 是否正确
```

**TEESimulator 状态**: ✅ 已正确实现

---

## 📋 完善建议

### 优先级 1 (必须修复)

1. **BootKey/BootHash 持久化**
   ```kotlin
   // 确保使用持久化存储，避免每次启动随机生成
   ```

2. **使用 Hardware Attestation Keybox**
   ```
   // 获取真实的 Hardware Attestation 证书链
   // 而不是 Software Attestation
   ```

### 优先级 2 (建议修复)

3. **Module Hash 缓存**
   ```kotlin
   // 缓存 moduleHash，确保多次 attestation 一致
   ```

4. **证书有效期检查**
   ```kotlin
   // 检查 keybox 证书是否过期
   // 提供警告或自动更新机制
   ```

### 优先级 3 (可选优化)

5. **添加更多日志**
   ```kotlin
   // 记录所有 attestation 字段的值
   // 便于调试和验证
   ```

6. **添加自检机制**
   ```kotlin
   // 启动时验证所有关键参数
   // 确保一致性
   ```

---

## 🎯 最终结论

### TEESimulator 的 KeyAttestation 防御完善度评估

| 评估维度 | 评分 | 说明 |
|---------|------|------|
| **证书链伪造** | 8/10 | ⚠️ 使用 Software Attestation 证书 |
| **Attestation 扩展字段** | 10/10 | ✅ 完整实现所有字段 |
| **RootOfTrust 伪造** | 7/10 | ⚠️ BootKey/BootHash 可能不一致 |
| **设备标识符伪造** | 10/10 | ✅ 完整实现 |
| **补丁级别伪造** | 10/10 | ✅ 完整实现 |
| **Module Hash** | 8/10 | ⚠️ 需要确保一致性 |
| **时间一致性** | 10/10 | ✅ 完整实现 |
| **Application ID** | 10/10 | ✅ 完整实现 |

**综合评分: 9/10**

### 回答蓝方的问题

**TEESimulator 是否完善？**

✅ **基本完善** - 实现了 KeyAttestation 的所有核心字段

⚠️ **存在风险** - BootKey/BootHash 和 Keybox 证书链可能被检测

**是否能防住 ChunQiu 的所有进攻性检测？**

✅ **大部分** - 可以通过基本的 KeyAttestation 验证

⚠️ **可能被高级检测发现** - 如果 ChunQiu 检查证书链类型或 BootKey 一致性

---

## 📝 行动计划

1. **立即**: 持久化 BootKey/BootHash
2. **短期**: 获取 Hardware Attestation Keybox
3. **中期**: 添加自检机制和更多日志
4. **长期**: 持续更新以应对新的检测技术
