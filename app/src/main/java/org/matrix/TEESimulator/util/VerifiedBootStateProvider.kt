package org.matrix.TEESimulator.util

import android.os.Build
import android.os.SystemProperties
import java.io.File
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Provides real Verified Boot state information from system properties.
 * 
 * This replaces hardcoded values in AttestationBuilder with actual device state,
 * making the attestation appear more legitimate to detection systems.
 * 
 * Verified Boot States:
 * - 0 (green): Verified - Boot chain verified by OEM key
 * - 1 (yellow): Self-signed - Boot chain verified by user-added key  
 * - 2 (orange): Unverified - Boot chain not verified (unlocked bootloader)
 * - 3 (red): Failed - Boot chain verification failed
 */
object VerifiedBootStateProvider {
    
    private const val TAG = "VerifiedBootState"
    
    /**
     * The verified boot state from system property ro.boot.verifiedbootstate.
     * Falls back to computing from other properties if not directly available.
     */
    val verifiedBootState: Int by lazy {
        readVerifiedBootState()
    }
    
    /**
     * Whether the device bootloader is locked.
     * Reads from ro.boot.flash.locked or ro.boot.vbmeta.device_state.
     */
    val deviceLocked: Boolean by lazy {
        readDeviceLockedState()
    }
    
    /**
     * The verified boot key hash from device tree or system property.
     * This is the public key used to verify the boot chain.
     */
    val verifiedBootKey: ByteArray by lazy {
        readVerifiedBootKey()
    }
    
    /**
     * The vbmeta digest from system property or computed from vbmeta partition.
     */
    val vbmetaDigest: ByteArray by lazy {
        readVbmetaDigest()
    }
    
    /**
     * The vbmeta flags indicating security state.
     */
    val vbmetaFlags: Int by lazy {
        readVbmetaFlags()
    }
    
    // --- Implementation ---
    
    private fun readVerifiedBootState(): Int {
        return try {
            // Primary: read directly from system property
            val state = SystemProperties.get("ro.boot.verifiedbootstate", "")
            
            val result = when (state.lowercase()) {
                "green" -> 0   // Verified
                "yellow" -> 1  // Self-signed
                "orange" -> 2  // Unverified (unlocked bootloader)
                "red" -> 3     // Failed
                else -> {
                    // Fallback: infer from bootloader lock state
                    if (deviceLocked) {
                        // Device is locked, assume verified
                        0
                    } else {
                        // Device is unlocked, report unverified
                        2
                    }
                }
            }
            
            SystemLogger.info("[$TAG] Verified boot state: '$state' -> $result (${stateToString(result)})")
            result
            
        } catch (e: Exception) {
            SystemLogger.error("[$TAG] Failed to read boot state", e)
            // Safe fallback: report unverified to avoid detection
            2
        }
    }
    
    private fun readDeviceLockedState(): Boolean {
        return try {
            // Primary: ro.boot.flash.locked (1 = locked, 0 = unlocked)
            val flashLocked = SystemProperties.get("ro.boot.flash.locked", "")
            if (flashLocked == "1") {
                SystemLogger.info("[$TAG] Device locked: true (from ro.boot.flash.locked)")
                return true
            }
            
            // Secondary: ro.boot.vbmeta.device_state
            val vbmetaState = SystemProperties.get("ro.boot.vbmeta.device_state", "")
            if (vbmetaState.equals("locked", ignoreCase = true)) {
                SystemLogger.info("[$TAG] Device locked: true (from vbmeta.device_state)")
                return true
            }
            
            // Tertiary: ro.boot.verifiedbootstate
            val bootState = SystemProperties.get("ro.boot.verifiedbootstate", "")
            if (bootState.equals("green", ignoreCase = true)) {
                SystemLogger.info("[$TAG] Device locked: true (inferred from verified state)")
                return true
            }
            
            // Check oem unlock status
            val oemUnlock = SystemProperties.get("ro.oem_unlock_supported", "")
            if (oemUnlock == "0") {
                SystemLogger.info("[$TAG] Device locked: true (OEM unlock not supported)")
                return true
            }
            
            // Default: report unlocked for safety
            SystemLogger.info("[$TAG] Device locked: false (no lock indicators found)")
            false
            
        } catch (e: Exception) {
            SystemLogger.error("[$TAG] Failed to read locked state", e)
            false
        }
    }
    
    private fun readVerifiedBootKey(): ByteArray {
        return try {
            // Primary: from device tree
            val keyFile = File("/proc/device-tree/firmware/android/verified-boot")
            if (keyFile.exists()) {
                val bytes = keyFile.readBytes().filter { it != 0.code.toByte() }.toByteArray()
                if (bytes.isNotEmpty()) {
                    SystemLogger.debug("[$TAG] Read verified boot key from device tree (${bytes.size} bytes)")
                    return bytes
                }
            }
            
            // Secondary: use bootKey from AndroidDeviceUtils (already handles persistence)
            val bootKey = AndroidDeviceUtils.bootKey
            SystemLogger.debug("[$TAG] Using bootKey from AndroidDeviceUtils (${bootKey.size} bytes)")
            bootKey
            
        } catch (e: Exception) {
            SystemLogger.error("[$TAG] Failed to read boot key", e)
            AndroidDeviceUtils.bootKey
        }
    }
    
    private fun readVbmetaDigest(): ByteArray {
        return try {
            // Primary: from system property
            val digestHex = SystemProperties.get("ro.boot.vbmeta.digest", "")
            if (digestHex.isNotEmpty() && digestHex.length == 64) {
                val bytes = digestHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                SystemLogger.debug("[$TAG] Read vbmeta digest from property (${bytes.size} bytes)")
                return bytes
            }
            
            // Fallback: use bootHash from AndroidDeviceUtils
            val bootHash = AndroidDeviceUtils.bootHash
            SystemLogger.debug("[$TAG] Using bootHash as vbmeta digest (${bootHash.size} bytes)")
            bootHash
            
        } catch (e: Exception) {
            SystemLogger.error("[$TAG] Failed to read vbmeta digest", e)
            AndroidDeviceUtils.bootHash
        }
    }
    
    private fun readVbmetaFlags(): Int {
        return try {
            val flags = SystemProperties.get("ro.boot.vbmeta.flags", "0")
            val result = flags.toIntOrNull() ?: 0
            SystemLogger.debug("[$TAG] Vbmeta flags: $flags -> $result")
            result
        } catch (e: Exception) {
            SystemLogger.error("[$TAG] Failed to read vbmeta flags", e)
            0
        }
    }
    
    /**
     * Validates that boot state is consistent with device properties.
     * Returns a validation result with any detected inconsistencies.
     */
    fun validateConsistency(): BootConsistencyResult {
        val issues = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        
        // Check if boot state matches lock state
        if (verifiedBootState == 0 && !deviceLocked) {
            warnings.add("Verified boot state but device reports unlocked")
        }
        
        if (verifiedBootState == 2 && deviceLocked) {
            warnings.add("Unverified boot state but device reports locked")
        }
        
        // Check vbmeta consistency
        if (verifiedBootState == 0 && vbmetaFlags == 0) {
            // Verified boot should have vbmeta flags set
            val hasVbmetaDigest = SystemProperties.get("ro.boot.vbmeta.digest", "").isNotEmpty()
            if (!hasVbmetaDigest) {
                issues.add("Verified boot state but no vbmeta digest found")
            }
        }
        
        // Check for red state (should never happen in production)
        if (verifiedBootState == 3) {
            issues.add("Boot verification failed (red state)")
        }
        
        return BootConsistencyResult(
            isValid = issues.isEmpty(),
            issues = issues,
            warnings = warnings,
            bootState = verifiedBootState,
            locked = deviceLocked
        )
    }
    
    /**
     * Converts boot state to human-readable string.
     */
    fun stateToString(state: Int): String {
        return when (state) {
            0 -> "Verified (green)"
            1 -> "Self-signed (yellow)"
            2 -> "Unverified (orange)"
            3 -> "Failed (red)"
            else -> "Unknown ($state)"
        }
    }
    
    /**
     * Logs detailed boot state information for debugging.
     */
    fun logBootStateInfo() {
        SystemLogger.info("[$TAG] === Verified Boot State Info ===")
        SystemLogger.info("[$TAG] Boot State: ${stateToString(verifiedBootState)}")
        SystemLogger.info("[$TAG] Device Locked: $deviceLocked")
        SystemLogger.info("[$TAG] Boot Key: ${verifiedBootKey.take(8).toByteArray().toHex()}...")
        SystemLogger.info("[$TAG] Vbmeta Digest: ${vbmetaDigest.take(8).toByteArray().toHex()}...")
        SystemLogger.info("[$TAG] Vbmeta Flags: $vbmetaFlags")
        
        val validation = validateConsistency()
        if (!validation.isValid) {
            SystemLogger.warning("[$TAG] Boot state validation issues: ${validation.issues}")
        }
        if (validation.warnings.isNotEmpty()) {
            SystemLogger.debug("[$TAG] Boot state warnings: ${validation.warnings}")
        }
    }
}

/**
 * Result of boot state consistency validation.
 */
data class BootConsistencyResult(
    val isValid: Boolean,
    val issues: List<String>,
    val warnings: List<String>,
    val bootState: Int,
    val locked: Boolean
) {
    val summary: String
        get() = buildString {
            appendLine("Boot Consistency: ${if (isValid) "VALID" else "INVALID"}")
            appendLine("  State: ${VerifiedBootStateProvider.stateToString(bootState)}")
            appendLine("  Locked: $locked")
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
