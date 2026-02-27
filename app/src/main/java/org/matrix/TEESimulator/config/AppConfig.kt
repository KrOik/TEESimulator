package org.matrix.TEESimulator.config

object AppConfig {
    // --- Configuration Paths ---
    const val CONFIG_PATH = "/data/adb/tricky_store"
    const val MODULES_DIR = "/data/adb/modules"
    
    // --- File Names ---
    const val TARGET_PACKAGES_FILE = "target.txt"
    const val TEE_STATUS_FILE = "tee_status.txt"
    const val PATCH_LEVEL_FILE = "security_patch.txt"
    const val SPOOF_FILE = "spoof.txt"
    const val DEFAULT_KEYBOX_FILE = "keybox.xml"

    // --- Reflection Class Names ---
    const val KEYMINT_INTERCEPTOR_CLASS = "org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor"
    const val INVALIDATE_PATCHED_CHAINS_METHOD = "invalidatePatchedChains"
}
