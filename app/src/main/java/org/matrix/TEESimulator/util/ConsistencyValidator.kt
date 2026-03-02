package org.matrix.TEESimulator.util

import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateChainValidator
import org.matrix.TEESimulator.pki.KeyBoxManager
import android.security.keystore.KeyProperties

data class ConsistencyReport(
    val overallScore: Double,
    val bootPropertiesScore: Double,
    val keyboxScore: Double,
    val moduleHashScore: Double,
    val timingScore: Double,
    val bootStateScore: Double,
    val issues: List<String>,
    val warnings: List<String>,
    val recommendations: List<String>
) {
    val isHealthy: Boolean get() = overallScore >= 8.0
    val needsAttention: Boolean get() = overallScore < 9.0
    
    val summary: String
        get() = buildString {
            appendLine("=== TEESimulator Consistency Report ===")
            appendLine("Overall Score: %.1f/10".format(overallScore))
            appendLine("Boot Properties: %.1f/10".format(bootPropertiesScore))
            appendLine("Boot State: %.1f/10".format(bootStateScore))
            appendLine("Keybox: %.1f/10".format(keyboxScore))
            appendLine("Module Hash: %.1f/10".format(moduleHashScore))
            appendLine("Timing Simulation: %.1f/10".format(timingScore))
            if (issues.isNotEmpty()) {
                appendLine("\n[ISSUES]")
                issues.forEach { appendLine("  ! $it") }
            }
            if (warnings.isNotEmpty()) {
                appendLine("\n[WARNINGS]")
                warnings.forEach { appendLine("  ? $it") }
            }
            if (recommendations.isNotEmpty()) {
                appendLine("\n[RECOMMENDATIONS]")
                recommendations.forEach { appendLine("  > $it") }
            }
        }
}

object ConsistencyValidator {
    
    fun performSelfCheck(): ConsistencyReport {
        val issues = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        val recommendations = mutableListOf<String>()
        
        val bootScore = validateBootProperties(issues, warnings, recommendations)
        val bootStateScore = validateBootState(issues, warnings, recommendations)
        val keyboxScore = validateKeybox(issues, warnings, recommendations)
        val moduleScore = validateModuleHash(issues, warnings, recommendations)
        val timingScore = validateTimingPatterns(issues, warnings, recommendations)
        
        val overallScore = (bootScore * 0.20 + bootStateScore * 0.15 + keyboxScore * 0.30 + moduleScore * 0.20 + timingScore * 0.15)
        
        if (overallScore < 9.0) {
            recommendations.add("Consider updating keybox to hardware attestation certificates")
        }
        if (bootScore < 9.0) {
            recommendations.add("Ensure boot properties are persisted for consistency")
        }
        if (timingScore < 8.0) {
            recommendations.add("Review timing simulation configuration")
        }
        
        return ConsistencyReport(
            overallScore = overallScore,
            bootPropertiesScore = bootScore,
            bootStateScore = bootStateScore,
            keyboxScore = keyboxScore,
            moduleHashScore = moduleScore,
            timingScore = timingScore,
            issues = issues,
            warnings = warnings,
            recommendations = recommendations
        )
    }
    
    private fun validateBootState(
        issues: MutableList<String>,
        warnings: MutableList<String>,
        recommendations: MutableList<String>
    ): Double {
        var score = 10.0
        
        val bootConsistency = VerifiedBootStateProvider.validateConsistency()
        if (!bootConsistency.isValid) {
            issues.addAll(bootConsistency.issues)
            score -= 2.0
        }
        warnings.addAll(bootConsistency.warnings)
        
        val deepValidation = BootPropertyValidator.performDeepValidation()
        if (!deepValidation.isValid) {
            issues.addAll(deepValidation.issues)
            score -= 1.5
        }
        warnings.addAll(deepValidation.warnings)
        
        if (!deepValidation.vbmetaValid) {
            score -= 0.5
        }
        if (!deepValidation.bootStateConsistent) {
            score -= 1.0
        }
        
        return score.coerceIn(0.0, 10.0)
    }
    
    private fun validateBootProperties(
        issues: MutableList<String>,
        warnings: MutableList<String>,
        recommendations: MutableList<String>
    ): Double {
        var score = 10.0
        
        val storedProps = BootPropertyStore.load()
        if (storedProps == null) {
            warnings.add("Boot properties not yet persisted")
            score -= 1.0
        } else {
            val currentBootKey = AndroidDeviceUtils.bootKey
            val currentBootHash = AndroidDeviceUtils.bootHash
            
            if (!currentBootKey.contentEquals(storedProps.bootKey.hexToByteArray())) {
                issues.add("BootKey inconsistency detected")
                score -= 2.0
            }
            if (!currentBootHash.contentEquals(storedProps.bootHash.hexToByteArray())) {
                issues.add("BootHash inconsistency detected")
                score -= 2.0
            }
            
            val ageMs = System.currentTimeMillis() - storedProps.timestamp
            val ageDays = ageMs / (1000 * 60 * 60 * 24)
            if (ageDays > 30) {
                warnings.add("Boot properties are $ageDays days old")
                score -= 0.5
            }
        }
        
        return score.coerceIn(0.0, 10.0)
    }
    
    private fun validateKeybox(
        issues: MutableList<String>,
        warnings: MutableList<String>,
        recommendations: MutableList<String>
    ): Double {
        var score = 10.0
        
        val keyboxStatus = KeyBoxManager.validateCurrentKeybox("keybox.xml")
        
        if (!keyboxStatus.isValid) {
            issues.addAll(keyboxStatus.issues)
            score -= 3.0
        }
        
        if (keyboxStatus.isAospSoftwareChain) {
            warnings.add("Using AOSP Software Attestation certificates")
            recommendations.add("Obtain hardware attestation keybox for better security")
            score -= 2.0
        }
        
        score -= (10 - keyboxStatus.securityScore) * 0.3
        
        return score.coerceIn(0.0, 10.0)
    }
    
    private fun validateModuleHash(
        issues: MutableList<String>,
        warnings: MutableList<String>,
        recommendations: MutableList<String>
    ): Double {
        var score = 10.0
        
        val cachedAttestation = DeviceAttestationService.CachedAttestationData
        if (cachedAttestation?.moduleHash != null) {
            val computedHash = AndroidDeviceUtils.moduleHash
            if (!cachedAttestation.moduleHash.contentEquals(computedHash)) {
                warnings.add("Module hash differs from TEE attestation")
                score -= 1.5
            }
        }
        
        return score.coerceIn(0.0, 10.0)
    }
    
    private fun validateTimingPatterns(
        issues: MutableList<String>,
        warnings: MutableList<String>,
        recommendations: MutableList<String>
    ): Double {
        val timingResult = TeeTimingSimulator.validateTimingPatterns()
        
        if (!timingResult.isValid) {
            issues.addAll(timingResult.issues)
        }
        warnings.addAll(timingResult.warnings)
        
        return timingResult.score
    }
    
    fun getOverallSecurityScore(): Double {
        return performSelfCheck().overallScore
    }
    
    fun logSecurityReport() {
        val report = performSelfCheck()
        SystemLogger.info(report.summary)
        
        if (report.needsAttention) {
            SystemLogger.warning("TEESimulator security score (${report.overallScore}) needs attention")
        } else {
            SystemLogger.info("TEESimulator security score: ${report.overallScore}/10 - Good")
        }
    }
}
