package org.matrix.TEESimulator.util

import kotlin.random.Random
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Simulates realistic TEE (Trusted Execution Environment) timing delays.
 * 
 * Real TEE operations have measurable latency due to:
 * - Context switch to secure world (TrustZone)
 * - Hardware cryptographic operations
 * - Secure memory allocation
 * - Inter-world communication overhead
 * 
 * This class provides timing simulation to make software-generated keys
 * appear more like genuine TEE-generated keys to timing-based detectors.
 */
object TeeTimingSimulator {
    
    private const val TAG = "TeeTimingSimulator"
    
    // Real TEE key generation typically takes 50-200ms
    // This is due to secure world context switch + hardware crypto operations
    private const val KEYGEN_MIN_MS = 50L
    private const val KEYGEN_MAX_MS = 200L
    
    // Certificate signing operations (ECDSA with P-256)
    private const val CERT_SIGN_MIN_MS = 15L
    private const val CERT_SIGN_MAX_MS = 80L
    
    // Operation creation (sign/verify) overhead
    private const val OP_CREATE_MIN_MS = 5L
    private const val OP_CREATE_MAX_MS = 30L
    
    // Simple operations like getKeyEntry
    private const val SIMPLE_OP_MIN_MS = 2L
    private const val SIMPLE_OP_MAX_MS = 15L
    
    // Cache recent delays to simulate realistic patterns
    // Real TEEs have consistent timing within short time windows
    private val recentDelays = mutableListOf<Long>()
    private const val MAX_CACHED_DELAYS = 10
    
    // Session seed for consistent timing within a session
    private var sessionSeed: Long = System.nanoTime()
    
    /**
     * Operation types that require different timing characteristics
     */
    enum class OperationType {
        KEY_GENERATION,     // Full key pair generation with attestation
        CERTIFICATE_SIGN,   // Certificate signing operation
        OPERATION_CREATE,   // Crypto operation initialization
        SIMPLE_QUERY,       // Simple keystore queries
        KEY_IMPORT,         // Key import operations
        ATTESTATION         // Attestation generation
    }
    
    /**
     * Simulates a TEE delay for the specified operation type.
     * Uses a realistic distribution with some variance.
     * 
     * @param operationType The type of operation being simulated
     * @param forceActualDelay If true, actually sleeps for the delay time
     * @return The simulated delay in milliseconds
     */
    fun simulateDelay(
        operationType: OperationType,
        forceActualDelay: Boolean = true
    ): Long {
        val delay = calculateRealisticDelay(operationType)
        
        if (forceActualDelay && delay > 0) {
            try {
                Thread.sleep(delay)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
        
        return delay
    }
    
    /**
     * Calculates a realistic delay based on operation type.
     * Uses patterns observed in real TEE implementations.
     */
    private fun calculateRealisticDelay(operationType: OperationType): Long {
        val (minMs, maxMs) = when (operationType) {
            OperationType.KEY_GENERATION -> KEYGEN_MIN_MS to KEYGEN_MAX_MS
            OperationType.CERTIFICATE_SIGN -> CERT_SIGN_MIN_MS to CERT_SIGN_MAX_MS
            OperationType.OPERATION_CREATE -> OP_CREATE_MIN_MS to OP_CREATE_MAX_MS
            OperationType.SIMPLE_QUERY -> SIMPLE_OP_MIN_MS to SIMPLE_OP_MAX_MS
            OperationType.KEY_IMPORT -> KEYGEN_MIN_MS / 2 to KEYGEN_MAX_MS / 2
            OperationType.ATTESTATION -> CERT_SIGN_MIN_MS * 2 to CERT_SIGN_MAX_MS * 2
        }
        
        // Generate delay with realistic distribution
        val baseDelay = generateRealisticDelay(minMs, maxMs)
        
        // Record for pattern analysis
        synchronized(recentDelays) {
            recentDelays.add(baseDelay)
            if (recentDelays.size > MAX_CACHED_DELAYS) {
                recentDelays.removeAt(0)
            }
        }
        
        SystemLogger.verbose("[$TAG] Simulated ${operationType.name} delay: ${baseDelay}ms")
        return baseDelay
    }
    
    private fun generateRealisticDelay(minMs: Long, maxMs: Long): Long {
        val range = maxMs - minMs
        val random = Random(sessionSeed++)
        
        val gaussian = random.nextDouble()
        val logNormalFactor = kotlin.math.exp(gaussian * 0.4)
        val normalizedDelay = minMs + (logNormalFactor * range / 2.5).toLong()
        
        val deviceOffset = (AndroidDeviceUtils.bootKey.firstOrNull()?.toInt()?.and(0xFF) ?: 128) % 8
        val delayWithOffset = normalizedDelay + deviceOffset
        
        val jitter = random.nextLong(-3, 4)
        
        return (delayWithOffset + jitter).coerceIn(minMs, maxMs)
    }
    
    /**
     * Gets timing statistics for diagnostic purposes.
     */
    fun getTimingStats(): TimingStats {
        synchronized(recentDelays) {
            if (recentDelays.isEmpty()) {
                return TimingStats(0.0, 0.0, 0L, 0L, 0)
            }
            
            val avg = recentDelays.average()
            val variance = recentDelays.map { (it - avg) * (it - avg) }.average()
            val stdDev = kotlin.math.sqrt(variance)
            
            return TimingStats(
                averageMs = avg,
                stdDevMs = stdDev,
                minMs = recentDelays.minOrNull() ?: 0,
                maxMs = recentDelays.maxOrNull() ?: 0,
                sampleCount = recentDelays.size
            )
        }
    }
    
    /**
     * Resets the timing simulator state.
     * Call this when starting a new session.
     */
    fun reset() {
        synchronized(recentDelays) {
            recentDelays.clear()
        }
        sessionSeed = System.nanoTime()
        SystemLogger.debug("[$TAG] Timing simulator reset")
    }
    
    /**
     * Checks if timing patterns look realistic.
     * Can be used for self-diagnosis.
     */
    fun validateTimingPatterns(): TimingValidationResult {
        val stats = getTimingStats()
        
        if (stats.sampleCount < 3) {
            return TimingValidationResult(
                isValid = true,
                score = 10.0,
                issues = emptyList(),
                warnings = listOf("Insufficient samples for timing validation")
            )
        }
        
        val issues = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        var score = 10.0
        
        // Check for too consistent timing (would indicate software simulation)
        if (stats.stdDevMs < 3.0 && stats.sampleCount >= 5) {
            issues.add("Timing variance too low (stdDev=${String.format("%.1f", stats.stdDevMs)}ms)")
            score -= 2.0
        }
        
        // Check for unrealistic timing
        if (stats.averageMs < 10.0) {
            warnings.add("Average delay very low (${String.format("%.1f", stats.averageMs)}ms)")
            score -= 1.0
        }
        
        // Check for too much variance (would indicate problems)
        if (stats.stdDevMs > stats.averageMs * 0.5) {
            warnings.add("High timing variance detected")
            score -= 0.5
        }
        
        return TimingValidationResult(
            isValid = score >= 7.0,
            score = score.coerceIn(0.0, 10.0),
            issues = issues,
            warnings = warnings
        )
    }
}

data class TimingStats(
    val averageMs: Double,
    val stdDevMs: Double,
    val minMs: Long,
    val maxMs: Long,
    val sampleCount: Int
) {
    val summary: String
        get() = buildString {
            appendLine("Timing Statistics:")
            appendLine("  Average: ${String.format("%.1f", averageMs)}ms")
            appendLine("  Std Dev: ${String.format("%.1f", stdDevMs)}ms")
            appendLine("  Range: ${minMs}ms - ${maxMs}ms")
            appendLine("  Samples: $sampleCount")
        }
}

data class TimingValidationResult(
    val isValid: Boolean,
    val score: Double,
    val issues: List<String>,
    val warnings: List<String>
) {
    val summary: String
        get() = buildString {
            appendLine("Timing Validation: ${if (isValid) "PASS" else "FAIL"} (score: ${String.format("%.1f", score)}/10)")
            if (issues.isNotEmpty()) {
                appendLine("Issues:")
                issues.forEach { appendLine("  ! $it") }
            }
            if (warnings.isNotEmpty()) {
                appendLine("Warnings:")
                warnings.forEach { appendLine("  ? $it") }
            }
        }
}
