package org.matrix.TEESimulator.pki

import java.security.MessageDigest
import java.security.cert.X509Certificate
import org.matrix.TEESimulator.logging.SystemLogger

data class RootCAResult(
    val isGoogleRootCA: Boolean,
    val fingerprint: String,
    val chainType: RootCAType,
    val warnings: List<String>
) {
    val summary: String
        get() = buildString {
            appendLine("Root CA Validation: ${if (isGoogleRootCA) "GOOGLE" else "UNKNOWN"}")
            appendLine("  Type: $chainType")
            appendLine("  Fingerprint: $fingerprint")
            if (warnings.isNotEmpty()) {
                appendLine("  Warnings:")
                warnings.forEach { appendLine("    ? $it") }
            }
        }
}

enum class RootCAType {
    GOOGLE_HARDWARE_ATTESTATION,
    GOOGLE_STRONGBOX,
    AOSP_SOFTWARE,
    UNKNOWN
}

object GoogleRootCAValidator {
    
    private const val TAG = "GoogleRootCA"
    
    private val KNOWN_GOOGLE_ROOT_CA_FINGERPRINTS = mapOf(
        "24C76F04366B58E871039CB79242E8BA9A48602D5A9E7F71BBEB156C06740496" to RootCAType.GOOGLE_HARDWARE_ATTESTATION,
        "4D9D904E5055D50F84A0E8CA1E4534A0CC7743B5CD3DE3E7D69C5D3B9D72A6E6" to RootCAType.GOOGLE_HARDWARE_ATTESTATION,
        "B85CB878ABC02A03E3674B61E063D87B8AD37E4E69CC6E25B9B49DD696FA5A0D" to RootCAType.GOOGLE_STRONGBOX
    )
    
    private val AOSP_SOFTWARE_ROOT_FINGERPRINTS = setOf(
        "DFB45E72E74AE0B5827331F1E5ED7BF254F6C5E0F87D6B51B374329378DFA727",
        "9F1C3E8F55A53F1BE6FC5F5918F429E28BF5A2F3E084B7F7C1A9F6C5D3E2B1A0"
    )
    
    fun validateGoogleRootCA(chain: List<X509Certificate>): RootCAResult {
        if (chain.isEmpty()) {
            return RootCAResult(
                isGoogleRootCA = false,
                fingerprint = "empty_chain",
                chainType = RootCAType.UNKNOWN,
                warnings = listOf("Certificate chain is empty")
            )
        }
        
        val rootCert = chain.last()
        val fingerprint = computeSha256Fingerprint(rootCert.encoded)
        
        val knownType = KNOWN_GOOGLE_ROOT_CA_FINGERPRINTS[fingerprint]
        val isAosp = AOSP_SOFTWARE_ROOT_FINGERPRINTS.contains(fingerprint)
        
        val chainType = when {
            knownType != null -> knownType
            isAosp -> RootCAType.AOSP_SOFTWARE
            else -> RootCAType.UNKNOWN
        }
        
        val isGoogleRootCA = knownType != null
        val warnings = mutableListOf<String>()
        
        if (!isGoogleRootCA && !isAosp) {
            warnings.add("Unknown root CA fingerprint: $fingerprint")
            SystemLogger.warning("[$TAG] Unknown root CA detected: $fingerprint")
        }
        
        if (isAosp) {
            warnings.add("Using AOSP Software Attestation root CA")
            SystemLogger.debug("[$TAG] AOSP Software root CA detected")
        }
        
        if (isGoogleRootCA) {
            SystemLogger.info("[$TAG] Valid Google Root CA detected: $chainType")
        }
        
        return RootCAResult(
            isGoogleRootCA = isGoogleRootCA,
            fingerprint = fingerprint,
            chainType = chainType,
            warnings = warnings
        )
    }
    
    fun getRootCAFingerprint(chain: List<X509Certificate>): String {
        if (chain.isEmpty()) return "empty"
        return computeSha256Fingerprint(chain.last().encoded)
    }
    
    fun isKnownRootCA(chain: List<X509Certificate>): Boolean {
        if (chain.isEmpty()) return false
        val fingerprint = computeSha256Fingerprint(chain.last().encoded)
        return KNOWN_GOOGLE_ROOT_CA_FINGERPRINTS.containsKey(fingerprint) ||
               AOSP_SOFTWARE_ROOT_FINGERPRINTS.contains(fingerprint)
    }
    
    fun getRootCAType(chain: List<X509Certificate>): RootCAType {
        val result = validateGoogleRootCA(chain)
        return result.chainType
    }
    
    private fun computeSha256Fingerprint(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        return digest.joinToString("") { "%02X".format(it) }
    }
    
    fun logRootCAInfo(chain: List<X509Certificate>) {
        val result = validateGoogleRootCA(chain)
        SystemLogger.info("[$TAG] === Root CA Info ===")
        SystemLogger.info("[$TAG] Type: ${result.chainType}")
        SystemLogger.info("[$TAG] Is Google: ${result.isGoogleRootCA}")
        SystemLogger.info("[$TAG] Fingerprint: ${result.fingerprint}")
        if (result.warnings.isNotEmpty()) {
            result.warnings.forEach { SystemLogger.warning("[$TAG] $it") }
        }
    }
}
