package org.matrix.TEESimulator.util

import java.io.File
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write
import org.json.JSONObject
import org.matrix.TEESimulator.config.AppConfig
import org.matrix.TEESimulator.logging.SystemLogger

data class BootProperties(
    val bootKey: String,
    val bootHash: String,
    val timestamp: Long = System.currentTimeMillis(),
    val source: String = "generated"
)

object BootPropertyStore {
    private const val STORE_DIR = "boot_properties"
    private const val STORE_FILE = "boot_properties.json"
    
    private val lock = ReentrantReadWriteLock()
    private var cachedProperties: BootProperties? = null
    
    private val storeFile: File
        get() = File(File(AppConfig.CONFIG_PATH, STORE_DIR), STORE_FILE)
    
    fun load(): BootProperties? {
        return lock.read {
            cachedProperties ?: runCatching {
                val file = storeFile
                if (!file.exists()) {
                    SystemLogger.debug("Boot properties file not found: ${file.absolutePath}")
                    return@runCatching null
                }
                
                val json = JSONObject(file.readText())
                BootProperties(
                    bootKey = json.getString("bootKey"),
                    bootHash = json.getString("bootHash"),
                    timestamp = json.optLong("timestamp", 0),
                    source = json.optString("source", "unknown")
                ).also {
                    cachedProperties = it
                    SystemLogger.debug("Loaded boot properties from ${file.absolutePath}")
                }
            }.getOrElse { e ->
                SystemLogger.error("Failed to load boot properties", e)
                null
            }
        }
    }
    
    fun save(props: BootProperties) {
        lock.write {
            runCatching {
                val file = storeFile
                file.parentFile?.mkdirs()
                
                val json = JSONObject().apply {
                    put("bootKey", props.bootKey)
                    put("bootHash", props.bootHash)
                    put("timestamp", props.timestamp)
                    put("source", props.source)
                }
                
                file.writeText(json.toString(2))
                cachedProperties = props
                
                SystemLogger.info("Saved boot properties to ${file.absolutePath}")
            }.getOrElse { e ->
                SystemLogger.error("Failed to save boot properties", e)
            }
        }
    }
    
    fun validateConsistency(currentBootKey: ByteArray, currentBootHash: ByteArray): ConsistencyResult {
        val stored = load()
        
        if (stored == null) {
            return ConsistencyResult.NoStoredData
        }
        
        val storedBootKey = stored.bootKey.hexToByteArray()
        val storedBootHash = stored.bootHash.hexToByteArray()
        
        val bootKeyMatch = storedBootKey.contentEquals(currentBootKey)
        val bootHashMatch = storedBootHash.contentEquals(currentBootHash)
        
        return when {
            bootKeyMatch && bootHashMatch -> ConsistencyResult.Consistent
            !bootKeyMatch && !bootHashMatch -> ConsistencyResult.BothMismatch(
                storedBootKey, storedBootHash, currentBootKey, currentBootHash
            )
            !bootKeyMatch -> ConsistencyResult.BootKeyMismatch(storedBootKey, currentBootKey)
            else -> ConsistencyResult.BootHashMismatch(storedBootHash, currentBootHash)
        }
    }
    
    fun getOrCreate(currentBootKey: ByteArray, currentBootHash: ByteArray): BootProperties {
        val stored = load()
        
        if (stored != null) {
            val storedBootKey = stored.bootKey.hexToByteArray()
            val storedBootHash = stored.bootHash.hexToByteArray()
            
            if (storedBootKey.contentEquals(currentBootKey) && 
                storedBootHash.contentEquals(currentBootHash)) {
                SystemLogger.debug("Using stored boot properties (consistent)")
                return stored
            }
            
            if (!storedBootKey.contentEquals(currentBootKey)) {
                SystemLogger.warning("BootKey mismatch: stored vs current. Using stored value for consistency.")
            }
            if (!storedBootHash.contentEquals(currentBootHash)) {
                SystemLogger.warning("BootHash mismatch: stored vs current. Using stored value for consistency.")
            }
            
            return stored
        }
        
        val newProps = BootProperties(
            bootKey = currentBootKey.toHex(),
            bootHash = currentBootHash.toHex(),
            timestamp = System.currentTimeMillis(),
            source = "first_run"
        )
        
        save(newProps)
        SystemLogger.info("Created new boot properties")
        
        return newProps
    }
    
    fun clear() {
        lock.write {
            runCatching {
                val file = storeFile
                if (file.exists()) {
                    file.delete()
                    SystemLogger.info("Cleared boot properties")
                }
                cachedProperties = null
            }.getOrElse { e ->
                SystemLogger.error("Failed to clear boot properties", e)
            }
        }
    }
}

sealed class ConsistencyResult {
    object Consistent : ConsistencyResult()
    object NoStoredData : ConsistencyResult()
    data class BootKeyMismatch(val stored: ByteArray, val current: ByteArray) : ConsistencyResult()
    data class BootHashMismatch(val stored: ByteArray, val current: ByteArray) : ConsistencyResult()
    data class BothMismatch(
        val storedBootKey: ByteArray, 
        val storedBootHash: ByteArray,
        val currentBootKey: ByteArray, 
        val currentBootHash: ByteArray
    ) : ConsistencyResult()
    
    val isConsistent: Boolean
        get() = this is Consistent || this is NoStoredData
    
    val description: String
        get() = when (this) {
            is Consistent -> "Boot properties are consistent"
            is NoStoredData -> "No stored boot properties found"
            is BootKeyMismatch -> "BootKey mismatch detected"
            is BootHashMismatch -> "BootHash mismatch detected"
            is BothMismatch -> "Both BootKey and BootHash mismatch detected"
        }
}
