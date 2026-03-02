package org.matrix.TEESimulator.pki

import java.security.cert.X509Certificate
import java.security.cert.CertificateException
import java.util.Date
import org.matrix.TEESimulator.logging.SystemLogger
import java.io.ByteArrayInputStream
import java.io.IOException

data class ValidationResult(
    val isValid: Boolean,
    val securityScore: Int,
    val issues: List<String>,
    val isAospSoftwareChain: Boolean,
    val derEncodingValid: Boolean = true
) {
    val summary: String
        get() = buildString {
            append("Validation Result: ${if (isValid) "VALID" else "INVALID"}\n")
            append("Security Score: $securityScore/10\n")
            append("AOSP Software Chain: $isAospSoftwareChain\n")
            append("DER Encoding: ${if (derEncodingValid) "VALID" else "INVALID"}\n")
            if (issues.isNotEmpty()) {
                append("Issues:\n")
                issues.forEach { append("  - $it\n") }
            }
        }
}

object CertificateChainValidator {
    
    private const val AOSP_SOFTWARE_SUBJECT_PATTERN = "Android Keystore Software Attestation"
    private const val HARDWARE_ATTESTATION_SUBJECT_PATTERN = "Android Keystore Hardware Attestation"
    
    fun isAospSoftwareChain(chain: List<X509Certificate>): Boolean {
        if (chain.isEmpty()) return false
        
        return chain.any { cert ->
            val subject = cert.subjectX500Principal.name
            subject.contains(AOSP_SOFTWARE_SUBJECT_PATTERN, ignoreCase = true)
        }
    }
    
    fun isHardwareAttestationChain(chain: List<X509Certificate>): Boolean {
        if (chain.isEmpty()) return false
        
        return chain.any { cert ->
            val subject = cert.subjectX500Principal.name
            subject.contains(HARDWARE_ATTESTATION_SUBJECT_PATTERN, ignoreCase = true) ||
            (!subject.contains("Software", ignoreCase = true) && 
             subject.contains("Attestation", ignoreCase = true))
        }
    }
    
    fun validateChain(chain: List<X509Certificate>): ValidationResult {
        val issues = mutableListOf<String>()
        var score = 10
        
        if (chain.isEmpty()) {
            return ValidationResult(
                isValid = false,
                securityScore = 0,
                issues = listOf("Certificate chain is empty"),
                isAospSoftwareChain = false
            )
        }
        
        val isAosp = isAospSoftwareChain(chain)
        val isHardware = isHardwareAttestationChain(chain)
        
        if (isAosp) {
            issues.add("Certificate chain uses AOSP Software Attestation certificates")
            score -= 3
            SystemLogger.warning("Keybox uses AOSP Software Attestation certificates - may be detected")
        }
        
        if (!isHardware && !isAosp) {
            issues.add("Certificate chain type is unknown")
            score -= 1
        }
        
        val now = Date()
        chain.forEachIndexed { index, cert ->
            val certName = if (index == 0) "Leaf" else if (index == chain.size - 1) "Root" else "Intermediate $index"
            
            if (now.before(cert.notBefore)) {
                issues.add("$certName certificate is not yet valid (notBefore: ${cert.notBefore})")
                score -= 2
            }
            
            if (now.after(cert.notAfter)) {
                issues.add("$certName certificate has expired (notAfter: ${cert.notAfter})")
                score -= 2
            }
            
            val daysUntilExpiry = ((cert.notAfter.time - now.time) / (1000 * 60 * 60 * 24)).toInt()
            if (daysUntilExpiry in 1..30) {
                issues.add("$certName certificate expires soon ($daysUntilExpiry days)")
                score -= 1
            }
        }
        
        for (i in 0 until chain.size - 1) {
            val issuer = chain[i].issuerX500Principal
            val subject = chain[i + 1].subjectX500Principal
            
            if (issuer != subject) {
                issues.add("Certificate chain break at index $i: issuer does not match next subject")
                score -= 2
            }
        }
        
        if (chain.isNotEmpty()) {
            val root = chain.last()
            if (root.issuerX500Principal != root.subjectX500Principal) {
                issues.add("Root certificate is not self-signed")
                score -= 1
            }
        }
        
        val derValid = validateDerEncoding(chain, issues)
        if (!derValid) {
            score -= 2
        }
        
        score = score.coerceIn(0, 10)
        
        return ValidationResult(
            isValid = score >= 5 && issues.none { it.contains("expired") || it.contains("chain break") } && derValid,
            securityScore = score,
            issues = issues,
            isAospSoftwareChain = isAosp,
            derEncodingValid = derValid
        )
    }
    
    private fun validateDerEncoding(chain: List<X509Certificate>, issues: MutableList<String>): Boolean {
        var allValid = true
        
        chain.forEachIndexed { index, cert ->
            val certName = if (index == 0) "Leaf" else if (index == chain.size - 1) "Root" else "Intermediate $index"
            
            try {
                val encoded = cert.encoded
                
                if (encoded.isEmpty()) {
                    issues.add("$certName certificate has empty DER encoding")
                    allValid = false
                    return@forEachIndexed
                }
                
                if (encoded[0] != 0x30.toByte()) {
                    issues.add("$certName certificate has invalid DER SEQUENCE tag")
                    allValid = false
                    return@forEachIndexed
                }
                
                validateDerLength(encoded, certName, issues)
                
                val redecoded = CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
                
                if (redecoded.encoded?.contentEquals(encoded) != true) {
                    issues.add("$certName certificate DER re-encoding mismatch")
                    allValid = false
                }
                
            } catch (e: CertificateException) {
                issues.add("$certName certificate DER encoding error: ${e.message}")
                allValid = false
            } catch (e: IOException) {
                issues.add("$certName certificate DER IO error: ${e.message}")
                allValid = false
            }
        }
        
        if (!validateIssuerSubjectDerMatch(chain, issues)) {
            allValid = false
        }
        
        if (!validateCriticalExtensions(chain, issues)) {
            allValid = false
        }
        
        return allValid
    }
    
    private fun validateIssuerSubjectDerMatch(chain: List<X509Certificate>, issues: MutableList<String>): Boolean {
        var allValid = true
        
        for (i in 0 until chain.size - 1) {
            val issuerDer = chain[i].issuerX500Principal.encoded
            val subjectDer = chain[i + 1].subjectX500Principal.encoded
            
            if (!issuerDer.contentEquals(subjectDer)) {
                issues.add("Certificate $i: Issuer DER encoding does not match Subject DER of cert ${i+1}")
                SystemLogger.error("DER encoding mismatch at index $i")
                SystemLogger.debug("  Issuer DER: ${bytesToHex(issuerDer).take(64)}...")
                SystemLogger.debug("  Subject DER: ${bytesToHex(subjectDer).take(64)}...")
                allValid = false
            }
        }
        
        return allValid
    }
    
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun validateCriticalExtensions(chain: List<X509Certificate>, issues: MutableList<String>): Boolean {
        var allValid = true
        
        chain.forEachIndexed { index, cert ->
            val certName = if (index == 0) "Leaf" else if (index == chain.size - 1) "Root" else "Intermediate $index"
            val criticalExtensions = cert.criticalExtensionOIDs
            
            if (index < chain.size - 1) {
                if (criticalExtensions?.contains("2.5.29.19") == false) {
                    issues.add("$certName certificate missing critical BasicConstraints extension")
                    allValid = false
                }
            }
            
            if (index == 0) {
                val hasKeyUsage = cert.keyUsage != null
                if (!hasKeyUsage) {
                    issues.add("$certName certificate missing KeyUsage extension")
                    allValid = false
                }
            }
        }
        
        return allValid
    }
    
    private fun validateDerLength(data: ByteArray, certName: String, issues: MutableList<String>) {
        if (data.size < 4) return
        
        val byte1 = data[1].toInt() and 0xFF
        when {
            byte1 < 0x80 -> {
                // Short form: length fits in single byte
            }
            byte1 == 0x81 -> {
                if (data.size < 3 + (data[2].toInt() and 0xFF)) {
                    issues.add("$certName certificate DER length overflow (0x81)")
                }
            }
            byte1 == 0x82 -> {
                if (data.size < 4) {
                    issues.add("$certName certificate DER truncated length field")
                    return
                }
                val length = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
                if (data.size < 4 + length) {
                    issues.add("$certName certificate DER length overflow (0x82)")
                }
            }
            byte1 > 0x82 -> {
                issues.add("$certName certificate uses unsupported DER length encoding (0x${byte1.toString(16)})")
            }
        }
    }
    
    fun getChainSecurityScore(chain: List<X509Certificate>): Int {
        return validateChain(chain).securityScore
    }
    
    fun getChainType(chain: List<X509Certificate>): ChainType {
        return when {
            isHardwareAttestationChain(chain) -> ChainType.HARDWARE_ATTESTATION
            isAospSoftwareChain(chain) -> ChainType.AOSP_SOFTWARE
            else -> ChainType.UNKNOWN
        }
    }
    
    fun getChainFingerprint(chain: List<X509Certificate>): String {
        if (chain.isEmpty()) return "empty"
        
        val root = chain.last()
        val fingerprint = java.security.MessageDigest.getInstance("SHA-256")
            .digest(root.encoded)
            .joinToString("") { "%02x".format(it) }
            .take(16)
        
        return "sha256:$fingerprint"
    }
}

enum class ChainType {
    HARDWARE_ATTESTATION,
    AOSP_SOFTWARE,
    UNKNOWN
}
