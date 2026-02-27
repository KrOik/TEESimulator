package org.matrix.TEESimulator.util

import android.os.SystemProperties
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Utility class for spoofing system properties to mimic a safe device state.
 * Refactored to use ShellUtils and secure escaping.
 */
object PropertySpoofer {

    /**
     * Applies default safe properties to the system using `resetprop`.
     * @param customProps Optional map of custom properties to apply.
     */
    fun spoofSafeProperties(customProps: Map<String, String> = emptyMap()) {
        SystemLogger.info("Starting property spoofing...")

        // 1. Get vbmeta size securely
        var vbmetaSize = "4096"
        try {
            // Sanitize slot suffix to prevent injection
            val slotSuffix = getProp("ro.boot.slot_suffix").replace(Regex("[^a-zA-Z0-9_]"), "")
            
            // Check if busybox exists before using it
            // Assuming busybox is available via PATH or standard locations.
            // For production, absolute paths are safer.
            // We use 'command -v' to check for existence in a shell-agnostic way (sh compatible)
            if (ShellUtils.exec("command -v busybox").isSuccess()) {
                val cmd = "busybox blockdev --getbsz /dev/block/by-name/vbmeta$slotSuffix"
                val result = ShellUtils.execRoot(cmd)

                if (result.isSuccess() && result.stdout.isNotEmpty()) {
                    val output = result.stdout[0].trim()
                    if (output.isNotBlank()) {
                        vbmetaSize = output
                    }
                } else {
                     SystemLogger.warning("Failed to get vbmeta size: ${result.stderr.joinToString("\n")}")
                }
            } else {
                SystemLogger.warning("busybox not found, using default vbmeta size.")
            }
        } catch (e: Exception) {
            SystemLogger.warning("Failed to get vbmeta size, using default: 4096", e)
        }

        // Check if resetprop exists
        if (!ShellUtils.exec("command -v resetprop").isSuccess()) {
            SystemLogger.error("resetprop binary not found! Property spoofing will fail.")
            return
        }

        // Batch command builder
        val batch = StringBuilder()

        queueResetProp("sys.usb.adb.disabled", " ", batch)

        queueResetProp("ro.boot.vbmeta.device_state", "locked", batch)
        queueResetProp("ro.boot.verifiedbootstate", "green", batch)
        queueResetProp("ro.boot.veritymode", "enforcing", batch)
        queueResetProp("ro.boot.warranty_bit", "0", batch)
        queueResetProp("ro.boot.flash.locked", "1", batch)

        containsResetProp("vendor.boot.bootmode", "recovery", "unknown", batch)
        containsResetProp("ro.boot.bootmode", "recovery", "unknown", batch)
        containsResetProp("ro.bootmode", "recovery", "unknown", batch)

        checkMissingProp("ro.boot.vbmeta.invalidate_on_error", "yes", batch)
        checkMissingProp("ro.boot.vbmeta.size", vbmetaSize, batch)
        checkMissingProp("ro.boot.vbmeta.hash_alg", "sha256", batch)
        checkMissingProp("ro.boot.vbmeta.avb_version", "1.2", batch)

        // Sync VerifiedBootHash
        queueResetProp("ro.boot.vbmeta.digest", AndroidDeviceUtils.bootHash.toHex(), batch)

        checkResetProp("vendor.boot.vbmeta.device_state", "locked", batch)
        checkResetProp("vendor.boot.verifiedbootstate", "green", batch)
        checkResetProp("ro.secureboot.lockstate", "locked", batch)
        checkResetProp("ro.boot.realmebootstate", "green", batch)
        checkResetProp("ro.vendor.boot.warranty_bit", "0", batch)
        checkResetProp("sys.oem_unlock_allowed", "0", batch)
        checkResetProp("ro.boot.realme.lockstate", "1", batch)
        checkResetProp("ro.build.tags", "release-keys", batch)
        checkResetProp("ro.crypto.state", "encrypted", batch)
        checkResetProp("ro.vendor.warranty_bit", "0", batch)
        checkResetProp("ro.force.debuggable", "0", batch)
        checkResetProp("ro.build.type", "user", batch)
        checkResetProp("ro.warranty_bit", "0", batch)
        checkResetProp("ro.debuggable", "0", batch)
        checkResetProp("ro.kernel.qemu", "", batch)
        checkResetProp("ro.adb.secure", "1", batch)
        checkResetProp("ro.secure", "1", batch)

        // Xiaomi: Ensure devicelock is locked
        queueResetProp("ro.secureboot.devicelock", "1", batch)

        // OnePlus logic - rewritten to be safer
        batch.append("p=\$(resetprop -n ro.boot.project_name); ")
        batch.append("case \"\$p\" in *_unlock) resetprop ro.boot.project_name \"\${p%_unlock}\";; esac; ")

        // Apply custom properties
        customProps.forEach { (key, value) ->
            queueResetProp(key, value, batch)
        }

        // Execute batch
        executeBatch(batch)

        SystemLogger.info("Property spoofing completed.")
    }

    private fun getProp(name: String): String {
        return try {
            SystemProperties.get(name, "")
        } catch (e: Exception) {
            SystemLogger.error("Failed to get property: $name", e)
            ""
        }
    }

    private fun queueResetProp(name: String, value: String, batch: StringBuilder) {
        // SECURITY: Escape BOTH name and value.
        batch.append("resetprop ${ShellUtils.escapeShellArg(name)} ${ShellUtils.escapeShellArg(value)}; ")
    }

    private fun executeBatch(batch: StringBuilder) {
        if (batch.isEmpty()) return
        
        try {
            val cmd = batch.toString()
            val result = ShellUtils.execRoot(cmd)
            
            if (!result.isSuccess()) {
                 SystemLogger.error("Batch resetprop exited with ${result.exitCode}: ${result.stderr.joinToString("\n")}")
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to execute batch resetprop", e)
        }
    }

    private fun containsResetProp(name: String, contains: String, newVal: String, batch: StringBuilder) {
        val value = getProp(name)
        if (value.contains(contains)) {
            queueResetProp(name, newVal, batch)
        }
    }

    private fun checkMissingProp(name: String, expected: String, batch: StringBuilder) {
        val value = getProp(name)
        if (value.isEmpty()) {
            queueResetProp(name, expected, batch)
        }
    }

    private fun checkResetProp(name: String, expected: String, batch: StringBuilder) {
        val value = getProp(name)
        if (value.isNotEmpty() && value != expected) {
            queueResetProp(name, expected, batch)
        }
    }
}
