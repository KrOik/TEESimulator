package org.matrix.TEESimulator.core

import org.matrix.TEESimulator.config.AppConfig
import org.matrix.TEESimulator.util.ShellUtils
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Detects conflicting modules and applications that may interfere with TEESimulator.
 * This module scans for known incompatible Magisk/KSU modules and apps.
 */
object ConflictDetector {

    /**
     * Entry point to detect all conflicts.
     * Checks both modules and applications.
     */
    fun detectConflicts() {
        SystemLogger.debug("Starting conflict detection...")
        
        // Ensure we can access module directory (root check)
        if (!ShellUtils.execRoot("[ -d \"${AppConfig.MODULES_DIR}\" ]").isSuccess()) {
            SystemLogger.error("Cannot access modules directory at ${AppConfig.MODULES_DIR}. Are we running with root?")
            // We continue to check apps, as that might still work if package manager is accessible
        } else {
            detectModuleConflicts()
        }
        
        detectAppConflicts()
        SystemLogger.debug("Conflict detection completed.")
    }

    private fun detectModuleConflicts() {
        // Check for standard conflicting modules
        ConflictConfig.CONFLICTING_MODULES.forEach { moduleName ->
            checkModule(moduleName, "Conflict", false)
        }

        // Check for forced remove modules
        ConflictConfig.FORCED_REMOVE_MODULES.forEach { moduleName ->
            checkModule(moduleName, "Critical Conflict", true)
        }
    }

    private fun checkModule(moduleName: String, severity: String, isCritical: Boolean) {
        val modulePath = "${AppConfig.MODULES_DIR}/$moduleName"
        // Use ShellUtils to check file existence with root permissions
        if (ShellUtils.fileExists(modulePath)) {
            val msg = "[TEESimulator-Conflict] Detected $severity Module: $moduleName"
            if (isCritical) {
                SystemLogger.error(msg)
                SystemLogger.error("It is recommended to disable or remove this module to ensure TEESimulator functions correctly.")
            } else {
                SystemLogger.warning(msg)
                SystemLogger.warning("It is recommended to disable or remove this module to ensure TEESimulator functions correctly.")
            }
        }
    }

    private fun detectAppConflicts() {
        ConflictConfig.CONFLICTING_APPS.forEach { packageName ->
            if (isPackageInstalled(packageName)) {
                SystemLogger.warning("[TEESimulator-Conflict] Detected Conflicting App: $packageName")
                SystemLogger.warning("This app is known to interfere with TEE simulation.")
            }
        }
    }

    private fun isPackageInstalled(packageName: String): Boolean {
        return try {
            // Use pm path via ShellUtils to check for package existence
            // "pm path" returns "package:/path/to/apk" if installed, or nothing/error if not.
            val result = ShellUtils.exec("pm path $packageName")
            result.isSuccess() && result.stdout.any { it.contains("package:") }
        } catch (e: Exception) {
            SystemLogger.error("Failed to check package: $packageName", e)
            false
        }
    }
}
