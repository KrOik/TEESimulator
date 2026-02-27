package org.matrix.TEESimulator.core

/**
 * Configuration for conflict detection.
 * Lists of modules and applications known to conflict with TEESimulator.
 */
object ConflictConfig {
    // Modules that cause conflicts and should be warned about
    val CONFLICTING_MODULES = listOf(
        "Yurikey",
        "xiaocaiye",
        "safetynet-fix",
        "vbmeta-fixer",
        "playintegrity",
        "integrity_box",
        "SukiSU_module",
        "Reset_BootHash",
        "Tricky_store-bm",
        "Hide_Bootloader",
        "ShamikoManager",
        "extreme_hide_root",
        "Tricky_Store-xiaoyi",
        "tricky_store_assistant",
        "extreme_hide_bootloader",
        "wjw_hiderootauxiliarymod"
    )

    // Modules that are critically incompatible and might need removal (in TSEE logic)
    val FORCED_REMOVE_MODULES = listOf(
        "TA_utl",
        ".TA_utl",
        "Yamabukiko"
    )

    // Applications that conflict with TEESimulator functionality
    val CONFLICTING_APPS = listOf(
        "com.lingqian.appbl",
        "com.topmiaohan.hidebllist"
    )
}
