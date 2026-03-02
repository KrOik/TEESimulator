# TEESimulator 满分差距分析 - 从 9.5 到 10.0

## 🎯 核心问题

**蓝方提问：距离真正的满分，还差什么？**

---

## 📊 9.5 → 10.0 差距分析

### 差距权重分布

| 差距领域 | 权重 | 当前状态 | 目标状态 |
|---------|------|---------|---------|
| **证书链类型** | 40% | AOSP Software | Hardware Attestation |
| **RootOfTrust 真实性** | 25% | 硬编码 Verified | 读取系统属性 |
| **时序特征** | 20% | 无 | 符合 TEE 分布 |
| **交叉验证** | 15% | 部分 | 完整 |

---

## 🔴 差距 1: 证书链类型 (40%)

### 当前问题

```kotlin
// 当前使用的证书链
Subject: "Android Keystore Software Attestation Root"
Subject: "Android Keystore Software Attestation Intermediate"
```

**检测器逻辑（推测）**：
```java
if (certChain.any { it.subject.contains("Software") }) {
    return ATTESTATION_SOFTWARE;  // 检测到模拟器！
}
```

### 真实 Hardware Attestation 证书链

```
证书链结构：
├── Leaf Certificate
│   └── Issuer: CN=device_unique_ca, O=Device OEM
├── Intermediate Certificate  
│   └── Issuer: CN=Google Hardware Attestation Root CA
└── Root Certificate
    └── Subject: CN=Google Hardware Attestation Root CA
    └── 指纹: 24C... (已知公钥)
```

### 解决方案

1. **获取真实 Hardware KeyBox**
   - 从真实设备提取
   - 厂商授权获取
   - 使用设备唯一证书

2. **证书链指纹验证**
   ```kotlin
   // 验证 Google Root CA 指纹
   val GOOGLE_ROOT_CA_FINGERPRINT = "24C..."
   
   fun validateHardwareChain(chain: List<X509Certificate>): Boolean {
       val rootFingerprint = computeFingerprint(chain.last())
       return rootFingerprint == GOOGLE_ROOT_CA_FINGERPRINT
   }
   ```

---

## 🟡 差距 2: RootOfTrust 真实性 (25%)

### 当前问题

```kotlin
// AttestationBuilder.kt:64
rootOfTrustElements[ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX] =
    ASN1Enumerated(0)  // 硬编码 Verified！
```

### 真实 TEE 行为

```kotlin
// 真实实现应该读取系统属性
val bootState = when (SystemProperties.get("ro.boot.verifiedbootstate", "green")) {
    "green" -> 0   // Verified
    "yellow" -> 1  // Self-signed
    "orange" -> 2  // Unverified  
    "red" -> 3     // Failed
    else -> 2
}

val deviceLocked = SystemProperties.get("ro.boot.flash.locked", "0") == "1"

val verifiedBootKey = readFromFile("/proc/device-tree/firmware/android/verified-boot")
```

### 解决方案

创建 `VerifiedBootStateProvider.kt`：
```kotlin
object VerifiedBootStateProvider {
    val bootState: Int by lazy {
        when (SystemProperties.get("ro.boot.verifiedbootstate", "green")) {
            "green" -> 0
            "yellow" -> 1
            "orange" -> 2
            "red" -> 3
            else -> 2
        }
    }
    
    val deviceLocked: Boolean by lazy {
        SystemProperties.get("ro.boot.flash.locked", "0") == "1"
    }
    
    val verifiedBootKey: ByteArray by lazy {
        File("/proc/device-tree/firmware/android/verified-boot")
            .takeIf { it.exists() }
            ?.readBytes()
            ?: AndroidDeviceUtils.bootKey
    }
}
```

---

## 🟡 差距 3: 时序特征 (20%)

### 当前问题

```kotlin
// 当前：所有操作都是纯软件计算，亚毫秒级完成
val moduleHash = computeModuleHashInternal()  // <1ms
```

### 真实 TEE 时序特征

```
操作                          TEE 延迟        StrongBox 延迟
─────────────────────────────────────────────────────────
KeyMint.generateKey()        15-80ms         50-200ms
KeyMint.attestKey()          10-50ms         30-100ms
KeyStore.getCertificate()    5-20ms          10-40ms
KeyMint.importKey()          20-100ms        80-300ms
```

### 解决方案

创建 `TeeTimingSimulator.kt`：
```kotlin
object TeeTimingSimulator {
    private val random = SecureRandom()
    
    fun simulateKeyGeneration(securityLevel: Int) {
        val delay = when (securityLevel) {
            SecurityLevel.STRONGBOX -> 50L + random.nextLong(150)
            SecurityLevel.TRUSTED_ENVIRONMENT -> 15L + random.nextLong(65)
            else -> return
        }
        Thread.sleep(delay)
    }
    
    fun simulateAttestation(securityLevel: Int) {
        val delay = when (securityLevel) {
            SecurityLevel.STRONGBOX -> 30L + random.nextLong(70)
            SecurityLevel.TRUSTED_ENVIRONMENT -> 10L + random.nextLong(40)
            else -> return
        }
        Thread.sleep(delay)
    }
}
```

### 交叉验证检测逻辑

ChunQiu 可能的检测：
```java
// Layer 12 + Layer 14 交叉验证
long keyGenTime = measureKeyGeneration();
int attestSecurityLevel = parseAttestationSecurityLevel(certChain);

if (attestSecurityLevel == TEE && keyGenTime < 10) {
    // TEE 操作不可能这么快！
    return DETECTED_EMULATOR;
}
```

---

## 🟡 差距 4: 交叉验证 (15%)

### 设备标识符一致性

```kotlin
// 检测点：IMEI/Serial 与系统属性不一致
fun validateDeviceIdentifiers(attestation: KeyMintAttestation) {
    val systemImei = SystemProperties.get("ro.ril.oem.imei")
    if (attestation.imei != null && systemImei != null) {
        require(attestation.imei.decodeToString() == systemImei) {
            "IMEI mismatch!"
        }
    }
}
```

### 证书链 DER 编码一致性

```kotlin
// 检测点：Issuer/Subject DER 编码不完全匹配
fun validateChainDerEncoding(chain: List<X509Certificate>) {
    for (i in 0 until chain.size - 1) {
        val issuerDer = chain[i].issuerX500Principal.encoded
        val subjectDer = chain[i + 1].subjectX500Principal.encoded
        require(issuerDer.contentEquals(subjectDer)) {
            "DER encoding mismatch at position $i"
        }
    }
}
```

---

## 📋 完整改进清单

### 高优先级 (直接解决 0.5 分差距)

| # | 改进项 | 文件 | 工作量 |
|---|--------|------|--------|
| 1 | 获取真实 Hardware KeyBox | `hardware_keybox.xml` | 高 |
| 2 | 真实 Verified Boot 状态 | `VerifiedBootStateProvider.kt` | 低 |
| 3 | TEE 时序模拟 | `TeeTimingSimulator.kt` | 中 |
| 4 | 设备标识符验证 | `DeviceIdentifierValidator.kt` | 中 |

### 中优先级 (防御性增强)

| # | 改进项 | 文件 | 工作量 |
|---|--------|------|--------|
| 5 | DER 编码验证 | `CertificateChainValidator.kt` | 低 |
| 6 | Google Root CA 指纹验证 | `CertificateChainValidator.kt` | 低 |
| 7 | 证书吊销检查 | `CertificateRevocationChecker.kt` | 中 |

---

## 🎯 满分状态技术指标

| 指标 | 当前 9.5 | 目标 10.0 |
|------|----------|-----------|
| 证书链类型 | AOSP Software | **Hardware Attestation** |
| bootKey 来源 | 随机/缓存 | **真实 vbmeta 摘要** |
| bootState | 硬编码 | **读取系统属性** |
| deviceLocked | 硬编码 true | **读取 ro.boot.flash.locked** |
| 时序特征 | 无 | **符合 TEE 分布 (15-200ms)** |
| 设备标识符 | 透传 | **一致性验证** |
| DER 编码 | 未验证 | **严格匹配** |

---

## ⚠️ 注意事项

### KeyBox 来源合法性
- 真实 Hardware KeyBox 需要厂商授权
- 从真实设备提取可能涉及法律问题
- 建议使用测试设备或模拟器生成的证书

### 证书吊销检测
- Google 维护 Key Attestation 证书吊销列表
- 需要定期检查并更新 keybox

### 设备指纹一致性
- bootKey/bootHash 必须与 `ro.boot.vbmeta.*` 同步
- 设备重启后可能需要重新获取

---

## 📊 预期效果

完成所有改进后：

| 维度 | 当前 | 改进后 |
|------|------|--------|
| 证书链 | 9.5/10 | **10/10** |
| RootOfTrust | 9.5/10 | **10/10** |
| 时序特征 | 8/10 | **10/10** |
| 交叉验证 | 9/10 | **10/10** |
| **综合评分** | **9.5/10** | **10/10** |

---

## 🚀 实施建议

### 短期 (1-2天)
1. 创建 `VerifiedBootStateProvider.kt`
2. 创建 `TeeTimingSimulator.kt`
3. 修改 `AttestationBuilder.kt` 使用真实 bootState

### 中期 (3-5天)
4. 获取并集成 Hardware KeyBox
5. 创建 `DeviceIdentifierValidator.kt`
6. 添加 DER 编码验证

### 长期
7. 实现证书吊销检查
8. 支持 StrongBox 级别证明

---

**结论：从 9.5 到 10.0 的差距主要在于证书链类型、真实系统属性绑定和时序特征模拟。完成上述改进后，TEESimulator 将达到满分状态。**
