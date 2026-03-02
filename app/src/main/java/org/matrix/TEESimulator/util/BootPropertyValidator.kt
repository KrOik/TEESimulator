package org.matrix.TEESimulator.util

import android.os.SystemProperties
import java.io.File
import java.security.MessageDigest
import org.matrix.TEESimulator.logging.SystemLogger

data class DeepBootValidationResult(
    val isValid: Boolean,
    val issues: List<String>,
    val warnings: List<String>,
    val vbmetaValid: Boolean,
    val bootStateConsistent: Boolean,
    val persistenceValid: Boolean
) {
    val summary: String
        get() = buildString {
            appendLine("Deep Boot Validation: ${if (isValid) "PASS" else "FAIL"}")
            appendLine("  Vbmeta Valid: $vbmetaValid")
            appendLine("  Boot State Consistent: $bootStateConsistent")
            appendLine("  Persistence Valid: $persistenceValid")
            if (issues.isNotEmpty()) {
                appendLine("  Issues:")
                issues.forEach { appendLine("    ! $it") }
            }
            if (warnings.isNotEmpty()) {
                appendLine("  Warnings:")
                warnings.forEach { appendLine("    ? $it") }
            }
        }
}

object BootPropertyValidator {
    
    private const val TAG = "BootPropValidator"
    
    fun performDeepValidation(): DeepBootValidationResult {
        val issues = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        
        val vbmetaValid = validateVbmetaProperties(issues, warnings)
        val bootStateConsistent = validateBootStateConsistency(issues, warnings)
        val persistenceValid = validatePersistenceConsistency(issues, warnings)
        
        return DeepBootValidationResult(
            isValid = issues.isEmpty(),
            issues = issues,
            warnings = warnings,
            vbmetaValid = vbmetaValid,
            bootStateConsistent = bootStateConsistent,
            persistenceValid = persistenceValid
        )
    }
    
    private fun validateVbmetaProperties(
        issues: MutableList<String>,
        warnings: MutableList<String>
    ): Boolean {
        var valid = true
        
        val vbmetaDigest = SystemProperties.get("ro.boot.vbmeta.digest", "")
        val vbmetaSize = SystemProperties.get("ro.boot.vbmeta.size", "")
        val vbmetaFlags = SystemProperties.get("ro.boot.vbmeta.flags", "")
        val vbmetaDeviceState = SystemProperties.get("ro.boot.vbmeta.device_state", "")
        
        if (!vbmetaDigest.isNullOrEmpty()) {
            val computedHash = computeVbmetaHash()
            val expectedDigest = vbmetaDigest.uppercase()
            val computedHex = computedHash.joinToString("") { "%02X".format(it) }
            
            if (computedHex != expectedDigest && computedHash.isNotEmpty()) {
                warnings.add("Vbmeta digest mismatch (may be normal on some devices)")
            }
        }
        
        if (vbmetaDeviceState.equals("locked", ignoreCase = true)) {
            val bootState = VerifiedBootStateProvider.verifiedBootState
            if (bootState == 2) {
                issues.add("Vbmeta reports locked but boot state is unverified")
                valid = false
            }
        }
        
        if (vbmetaFlags.isNotEmpty()) {
            SystemLogger.debug("[$TAG] Vbmeta flags: $vbmetaFlags")
        }
        
        return valid
    }
    
    private fun validateBootStateConsistency(
        issues: MutableList<String>,
        warnings: MutableList<String>
    ): Boolean {
        var consistent = true
        
        val bootState = VerifiedBootStateProvider.verifiedBootState
        val deviceLocked = VerifiedBootStateProvider.deviceLocked
        
        if (bootState == 0 && !deviceLocked) {
            warnings.add("Boot state is verified but device reports unlocked")
        }
        
        if (bootState == 2 && deviceLocked) {
            warnings.add("Boot state is unverified but device reports locked")
        }
        
        if (bootState == 3) {
            issues.add("Boot verification failed (red state)")
            consistent = false
        }
        
        val vbmetaDeviceState = SystemProperties.get("ro.boot.vbmeta.device_state", "")
        if (bootState == 0 && vbmetaDeviceState.equals("unlocked", ignoreCase = true)) {
            issues.add("Boot state is verified but vbmeta reports unlocked")
            consistent = false
        }
        
        return consistent
    }
    
    private fun validatePersistenceConsistency(
        issues: MutableList<String>,
        warnings: MutableList<String>
    ): Boolean {
        var valid = true
        
        val storedProps = BootPropertyStore.load()
        if (storedProps == null) {
            warnings.add("No persisted boot properties found")
            return true
        }
        
        val currentBootKey = AndroidDeviceUtils.bootKey
        val currentBootHash = AndroidDeviceUtils.bootHash
        
        if (!currentBootKey.contentEquals(storedProps.bootKey.hexToByteArray())) {
            warnings.add("BootKey changed since last boot (may indicate device reboot)")
        }
        
        if (!currentBootHash.contentEquals(storedProps.bootHash.hexToByteArray())) {
            warnings.add("BootHash changed since last boot (may indicate vbmeta update)")
        }
        
        val ageMs = System.currentTimeMillis() - storedProps.timestamp
        val ageDays = ageMs / (1000 * 60 * 60 * 24)
        if (ageDays > 30) {
            warnings.add("Boot properties are $ageDays days old")
        }
        
        return valid
    }
    
    private fun computeVbmetaHash(): ByteArray {
        return try {
            val vbmetaPaths = listOf(
                "/dev/block/by-name/vbmeta",
                "/dev/block/by-name/vbmeta_a",
                "/dev/block/by-name/vbmeta_b"
            )
            
            for (path in vbmetaPaths) {
                val vbmetaFile = File(path)
                if (vbmetaFile.exists()) {
                    val bytes = vbmetaFile.inputStream().use { it.readBytes() }
                    if (bytes.isNotEmpty()) {
                        return MessageDigest.getInstance("SHA-256").digest(bytes)
                    }
                }
            }
            
            ByteArray(0)
        } catch (e: Exception) {
            SystemLogger.debug("[$TAG] Could not compute vbmeta hash: ${e.message}")
            ByteArray(0)
        }
    }
    
    fun logDeepValidation() {
        val result = performDeepValidation()
        SystemLogger.info("[$TAG] === Deep Boot Validation ===")
        SystemLogger.info("[$TAG] Valid: ${result.isValid}")
        SystemLogger.info("[$TAG] Vbmeta: ${result.vbmetaValid}")
        SystemLogger.info("[$TAG] Boot State Consistent: ${result.bootStateConsistent}")
        SystemLogger.info("[$TAG] Persistence: ${result.persistenceValid}")
        
        if (result.issues.isNotEmpty()) {
            result.issues.forEach { SystemLogger.warning("[$TAG] Issue: $it") }
        }
        if (result.warnings.isNotEmpty()) {
            result.warnings.forEach { SystemLogger.debug("[$TAG] Warning: $it") }
        }
    }
}
