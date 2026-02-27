package org.matrix.TEESimulator.config

import android.content.pm.IPackageManager
import android.os.Build
import android.os.FileObserver
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ServiceManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.KeyBoxManager
import org.matrix.TEESimulator.util.PropertySpoofer

/**
 * Manages application configuration, including which packages to process, what operation mode to
 * use, and custom security patch levels. It uses a FileObserver to dynamically reload settings when
 * configuration files change.
 */
object ConfigurationManager {

    /** Defines the processing mode for a given package. */
    enum class Mode {
        /** Automatically decide between GENERATE and PATCH based on TEE status. */
        AUTO,
        /** Patch the attestation of an existing certificate chain. */
        PATCH,
        /** Generate a new certificate chain from scratch. */
        GENERATE,
    }

    private val configRoot = File(AppConfig.CONFIG_PATH)

    // --- In-Memory Configuration State ---
    @Volatile private var packageModes = mapOf<String, Mode>()
    @Volatile private var packageKeyboxes = mapOf<String, String>()
    @Volatile private var isTeeBroken: Boolean? = null
    @Volatile private var globalCustomPatchLevel: CustomPatchLevel? = null
    @Volatile private var packagePatchLevels = mapOf<String, CustomPatchLevel>()
    @Volatile private var spoofProperties = mapOf<String, String>()

    // Cache for UID to package name resolution.
    private val uidToPackagesCache = ConcurrentHashMap<Int, Array<String>>()

    private const val RECOVERY_DELAY_MS = 2000L
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * Initializes the configuration manager by loading all settings from disk and starting the file
     * observer to watch for changes.
     */
    fun initialize() {
        configRoot.mkdirs()
        SystemLogger.info("Configuration root is: ${configRoot.absolutePath}")

        // First, ensure the package manager service is running, as the TEE check depends on it.
        // This prevents a race condition on startup.
        SystemLogger.info("Waiting for PackageManagerService to be ready...")
        if (getPackageManager() == null) {
            SystemLogger.error(
                "PackageManagerService is not available. TEE check will likely fail."
            )
        } else {
            SystemLogger.info("PackageManagerService is ready.")
        }

        // Start watching BEFORE loading to avoid race conditions during startup
        ConfigObserver.startWatching()

        // Initial load of all configuration files.
        reloadAllConfigs()

        SystemLogger.info("Configuration initialized and file observer started.")
    }

    private fun reloadAllConfigs() {
        if (!configRoot.exists()) {
            SystemLogger.warning("Config root missing during reload: ${configRoot.absolutePath}")
            return
        }
        loadTargetPackages(File(configRoot, AppConfig.TARGET_PACKAGES_FILE))
        loadPatchLevelConfig(File(configRoot, AppConfig.PATCH_LEVEL_FILE))
        loadSpoofConfig(File(configRoot, AppConfig.SPOOF_FILE))
        storeTeeStatus() // Check and store the current TEE status.
    }

    /**
     * Determines the keybox file to be used for a given UID. It maps the UID to its package(s) and
     * checks for a specific keybox mapping.
     *
     * @param uid The calling UID.
     * @return The name of the keybox file, or the default if none is specified.
     */
    fun getKeyboxFileForUid(uid: Int): String {
        val packages = getPackagesForUid(uid)
        return packages.firstNotNullOfOrNull { pkg -> packageKeyboxes[pkg] } ?: AppConfig.DEFAULT_KEYBOX_FILE
    }

    /** Determines if the certificate for a given UID needs to be patched. */
    fun shouldPatch(uid: Int): Boolean = getPackageModeForUid(uid) == Mode.PATCH

    /** Determines if a new certificate needs to be generated for a given UID. */
    fun shouldGenerate(uid: Int): Boolean = getPackageModeForUid(uid) == Mode.GENERATE

    /** Determines if no operation is needed for a given UID. */
    fun shouldSkipUid(uid: Int): Boolean = getPackageModeForUid(uid) == null

    /** Resolves the operating mode for a given UID based on its packages and the TEE status. */
    private fun getPackageModeForUid(uid: Int): Mode? {
        val packages = getPackagesForUid(uid)
        if (packages.isEmpty()) return null

        // Lazily load TEE status if it hasn't been checked yet.
        if (isTeeBroken == null) loadTeeStatus()

        // Find the first configured mode for any of the UID's packages.
        for (pkg in packages) {
            when (packageModes[pkg]) {
                Mode.GENERATE -> return Mode.GENERATE
                Mode.PATCH -> return Mode.PATCH
                Mode.AUTO -> return if (isTeeBroken == true) Mode.GENERATE else Mode.PATCH
                null -> continue // No config for this package, check the next one.
            }
        }
        return null // No configuration found for this UID.
    }

    /**
     * Retrieves the custom patch level configuration for a given UID. It first checks for a
     * package-specific override and falls back to the global configuration.
     *
     * @param uid The UID of the calling application.
     * @return The applicable [CustomPatchLevel], or null if no custom configuration exists.
     */
    fun getPatchLevelForUid(uid: Int): CustomPatchLevel? {
        val packages = getPackagesForUid(uid)
        // Find the first package-specific configuration for this UID.
        val packageSpecificPatchLevel =
            packages.firstNotNullOfOrNull { pkg -> packagePatchLevels[pkg] }
        return packageSpecificPatchLevel ?: globalCustomPatchLevel
    }

    /**
     * Loads and parses the `target.txt` file, which defines the processing mode and keybox file for
     * each package.
     */
    private fun loadTargetPackages(file: File) {
        if (!file.exists()) {
            SystemLogger.warning("Configuration file not found: ${file.absolutePath}")
            return
        }

        val newModes = mutableMapOf<String, Mode>()
        val newKeyboxes = mutableMapOf<String, String>()
        var currentKeybox = AppConfig.DEFAULT_KEYBOX_FILE
        val keyboxRegex = Regex("^\\[([a-zA-Z0-9_.-]+\\.xml)]$")

        try {
            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                // Check if the line defines a new keybox scope.
                keyboxRegex.find(trimmedLine)?.let {
                    currentKeybox = it.groupValues[1]
                    SystemLogger.info("Switching to keybox context: $currentKeybox")
                    return@forEach
                }

                when {
                    // Suffix '!' means force GENERATE mode.
                    trimmedLine.endsWith("!") -> {
                        val pkg = trimmedLine.removeSuffix("!").trim()
                        newModes[pkg] = Mode.GENERATE
                        newKeyboxes[pkg] = currentKeybox
                    }
                    // Suffix '?' means force PATCH mode.
                    trimmedLine.endsWith("?") -> {
                        val pkg = trimmedLine.removeSuffix("?").trim()
                        newModes[pkg] = Mode.PATCH
                        newKeyboxes[pkg] = currentKeybox
                    }
                    // No suffix means AUTO mode.
                    else -> {
                        newModes[trimmedLine] = Mode.AUTO
                        newKeyboxes[trimmedLine] = currentKeybox
                    }
                }
            }

            // Atomically update the configuration maps.
            packageModes = newModes
            packageKeyboxes = newKeyboxes
            uidToPackagesCache.clear() // Invalidate cache as package settings have changed.
            SystemLogger.info("Successfully loaded ${newModes.size} package configurations.")
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    /**
     * Loads and parses the `security_patch.txt` file, which can define both global and per-package
     * security patch levels.
     */
    private fun loadPatchLevelConfig(file: File) {
        if (!file.exists()) {
            globalCustomPatchLevel = null
            packagePatchLevels = emptyMap()
            return
        }

        try {
            val newPackageLevels = mutableMapOf<String, CustomPatchLevel>()
            var currentContext = "" // Empty string for global context
            val contextLines = mutableMapOf<String, MutableList<String>>()
            val contextRegex = Regex("^\\[([a-zA-Z0-9_.-]+)]$")

            // First pass: group lines by context (global or package-specific).
            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                contextRegex.find(trimmedLine)?.let { currentContext = it.groupValues[1] }
                    ?: run {
                        contextLines
                            .computeIfAbsent(currentContext) { mutableListOf() }
                            .add(trimmedLine)
                    }
            }

            // Helper function to parse a set of lines into a CustomPatchLevel object.
            fun parseLines(lines: List<String>?): CustomPatchLevel? {
                if (lines.isNullOrEmpty()) return null

                // Handle simple case: one line sets the patch level for all components.
                if (lines.size == 1 && '=' !in lines[0]) {
                    return CustomPatchLevel(
                        system = null,
                        vendor = null,
                        boot = null,
                        all = lines[0],
                    )
                }

                // Handle key-value pair configuration.
                val map =
                    lines
                        .mapNotNull {
                            val parts = it.split('=', limit = 2)
                            if (parts.size == 2) parts[0].trim().lowercase() to parts[1].trim()
                            else null
                        }
                        .toMap()

                val all = map["all"]
                return CustomPatchLevel(
                    system = map["system"] ?: all,
                    vendor = map["vendor"] ?: all,
                    boot = map["boot"] ?: all,
                    all = all,
                )
            }

            // Parse global and per-package configurations.
            var newGlobalLevel = parseLines(contextLines[""])
            // TrickyAddon writes Pixel bulletin dates for boot/vendor but system=prop
            // resolves to the real device prop — force boot/vendor through the same path
            // to prevent cross-component date mismatches on non-Pixel devices.
            if (newGlobalLevel?.system.equals("prop", ignoreCase = true)) {
                SystemLogger.info("system=prop: forcing boot/vendor to derive from device props (were: boot=${newGlobalLevel?.boot}, vendor=${newGlobalLevel?.vendor})")
                newGlobalLevel = newGlobalLevel?.copy(boot = "prop", vendor = "prop")
            }
            contextLines.remove("") // Remove global context to iterate over packages next

            for ((pkg, lines) in contextLines) {
                parseLines(lines)?.let { newPackageLevels[pkg] = it }
            }

            // Atomically update the configuration state.
            globalCustomPatchLevel = newGlobalLevel
            packagePatchLevels = newPackageLevels

            SystemLogger.info(
                "Loaded custom security patch levels: global config exists=${newGlobalLevel != null}, " +
                    "${newPackageLevels.size} package-specific configs."
            )
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    /**
     * Loads and parses the `spoof.txt` file, which defines custom system properties to be spoofed.
     * The file format is key=value.
     */
    private fun loadSpoofConfig(file: File) {
        if (!file.exists()) {
            spoofProperties = emptyMap()
            // If the file is missing, we revert to default spoofing.
            PropertySpoofer.spoofSafeProperties(spoofProperties)
            return
        }

        try {
            val newProperties = mutableMapOf<String, String>()
            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                val parts = trimmedLine.split('=', limit = 2)
                if (parts.size == 2) {
                    newProperties[parts[0].trim()] = parts[1].trim()
                }
            }
            spoofProperties = newProperties
            SystemLogger.info("Loaded ${newProperties.size} custom spoof properties.")
            PropertySpoofer.spoofSafeProperties(spoofProperties)
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    /** Checks the device's TEE status and writes the result to a file for persistence. */
    private fun storeTeeStatus() {
        val statusFile = File(configRoot, AppConfig.TEE_STATUS_FILE)
        isTeeBroken = !DeviceAttestationService.isTeeFunctional
        try {
            statusFile.writeText("tee_broken=$isTeeBroken")
            SystemLogger.info("TEE status stored: isTeeBroken=$isTeeBroken")
        } catch (e: Exception) {
            SystemLogger.error("Failed to write TEE status to file.", e)
        }
    }

    /** Loads the TEE status from the file. */
    private fun loadTeeStatus() {
        val statusFile = File(configRoot, AppConfig.TEE_STATUS_FILE)
        isTeeBroken =
            if (statusFile.exists()) {
                statusFile.readText().trim() == "tee_broken=true"
            } else {
                null // Status is unknown.
            }
    }

    /**
     * A Self-Healing FileObserver that survives directory destruction.
     * Monitors the configuration directory for changes and triggers reloads of the relevant settings.
     */
    private object ConfigObserver : FileObserver(configRoot, CLOSE_WRITE or MOVED_TO or DELETE or DELETE_SELF) {
        
        override fun onEvent(event: Int, path: String?) {
            // Mask the event to get the low-order bits
            val type = event and ALL_EVENTS

            // 1. Handle directory destruction (DELETE_SELF)
            if (type == DELETE_SELF && path == null) {
                SystemLogger.error("CRITICAL: Configuration directory deleted! Stopping observer and scheduling recovery.")
                stopWatching()
                scheduleRecovery()
                return
            }

            // 2. Ignore unrelated events
            if (path == null) return

            SystemLogger.info("Configuration file change detected: $path (event: $event)")
            val file = File(configRoot, path)

            // 3. Handle file changes
            when (path) {
                AppConfig.TARGET_PACKAGES_FILE -> if (type != DELETE) loadTargetPackages(file)
                AppConfig.PATCH_LEVEL_FILE -> if (type != DELETE) loadPatchLevelConfig(file)
                AppConfig.SPOOF_FILE -> loadSpoofConfig(File(configRoot, AppConfig.SPOOF_FILE))
                else -> {
                    if (path.endsWith(".xml")) {
                        SystemLogger.info("Keybox file change: $path. Invalidating cache.")
                        KeyBoxManager.invalidateCache(path)
                        // Invalidate cached certificate chains in the interceptor
                        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.R) {
                            try {
                                val interceptorClass = Class.forName(AppConfig.KEYMINT_INTERCEPTOR_CLASS)
                                val method = interceptorClass.getMethod(AppConfig.INVALIDATE_PATCHED_CHAINS_METHOD, String::class.java)
                                method.invoke(null, "keybox change: $path")
                            } catch (e: Exception) {
                                SystemLogger.warning("Could not invalidate patched chains: ${e.message}")
                            }
                        }
                    }
                }
            }
        }

        /**
         * Polls until the directory is recreated, then restarts the observer.
         */
        private fun scheduleRecovery() {
            mainHandler.postDelayed(object : Runnable {
                override fun run() {
                    if (configRoot.exists() && configRoot.isDirectory) {
                        SystemLogger.info("Configuration directory restored. Resurrecting observer...")
                        // Reload all configs to ensure state is fresh
                        reloadAllConfigs()
                        // Restart watching
                        startWatching() 
                    } else {
                        SystemLogger.warning("Waiting for config directory recovery...")
                        mainHandler.postDelayed(this, RECOVERY_DELAY_MS)
                    }
                }
            }, RECOVERY_DELAY_MS)
        }
    }

    // --- System Service Utilities ---

    private var iPackageManager: IPackageManager? = null
    private val pmDeathRecipient =
        object : IBinder.DeathRecipient {
            override fun binderDied() {
                (iPackageManager as? IBinder)?.unlinkToDeath(this, 0)
                iPackageManager = null
                SystemLogger.warning("Package manager service died. Will try to reconnect.")
            }
        }

    /** Retrieves an instance of the IPackageManager service. */
    fun getPackageManager(): IPackageManager? {
        if (iPackageManager == null) {
            // Use a robust method to get the service binder.
            val binder = waitForSystemService("package") ?: return null
            binder.linkToDeath(pmDeathRecipient, 0)
            iPackageManager = IPackageManager.Stub.asInterface(binder)
        }
        return iPackageManager
    }

    /** Retrieves the package names associated with a UID. */
    fun getPackagesForUid(uid: Int): Array<String> {
        return uidToPackagesCache.getOrPut(uid) {
            try {
                getPackageManager()?.getPackagesForUid(uid) ?: emptyArray()
            } catch (e: Exception) {
                SystemLogger.warning("Failed to get packages for UID $uid", e)
                emptyArray()
            }
        }
    }

    /** Waits for a system service to become available, with retries. */
    private fun waitForSystemService(name: String): IBinder? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return ServiceManager.waitForService(name)
        }
        // Fallback for older Android versions.
        repeat(70) {
            val service = ServiceManager.getService(name)
            if (service != null) return service
            Thread.sleep(500)
        }
        SystemLogger.error("Failed to get system service after multiple retries: $name")
        return null
    }
}

/** Data class representing custom security patch level overrides. */
data class CustomPatchLevel(
    val system: String?,
    val vendor: String?,
    val boot: String?,
    val all: String?,
)
