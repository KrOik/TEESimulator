package org.matrix.TEESimulator.util

import android.os.Build
import android.os.SystemProperties
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.SystemLogger

data class IdentifierValidationResult(
    val isValid: Boolean,
    val issues: List<String>,
    val warnings: List<String>
) {
    val summary: String
        get() = buildString {
            appendLine("Identifier Validation: ${if (isValid) "PASS" else "FAIL"}")
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

object DeviceIdentifierValidator {
    
    private const val TAG = "DeviceIdValidator"
    
    fun validateAttestationIdentifiers(attestation: KeyMintAttestation): IdentifierValidationResult {
        val issues = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        
        validateImei(attestation, issues, warnings)
        validateSerial(attestation, issues, warnings)
        validateBrand(attestation, issues, warnings)
        validateDevice(attestation, issues, warnings)
        validateProduct(attestation, issues, warnings)
        validateModel(attestation, issues, warnings)
        validateManufacturer(attestation, issues, warnings)
        
        return IdentifierValidationResult(
            isValid = issues.isEmpty(),
            issues = issues,
            warnings = warnings
        )
    }
    
    private fun validateImei(
        attestation: KeyMintAttestation,
        issues: MutableList<String>,
        warnings: MutableList<String>
    ) {
        attestation.imei?.let { attestationImei ->
            val systemImei = getSystemImei()
            if (systemImei != null) {
                val attestationStr = attestationImei.decodeToString()
                if (attestationStr != systemImei) {
                    issues.add("IMEI mismatch: attestation=$attestationStr, system=$systemImei")
                }
            }
            
            attestation.secondImei?.let { secondImei ->
                val systemImei2 = getSystemImei2()
                if (systemImei2 != null) {
                    val secondStr = secondImei.decodeToString()
                    if (secondStr != systemImei2) {
                        warnings.add("Second IMEI mismatch: attestation=$secondStr, system=$systemImei2")
                    }
                }
            }
        }
    }
    
    private fun validateSerial(
        attestation: KeyMintAttestation,
        issues: MutableList<String>,
        warnings: MutableList<String>
    ) {
        attestation.serial?.let { attestationSerial ->
            val systemSerial = getSystemSerial()
            if (systemSerial != null) {
                val attestationStr = attestationSerial.decodeToString()
                if (attestationStr != systemSerial) {
                    issues.add("Serial mismatch: attestation=$attestationStr, system=$systemSerial")
                }
            }
        }
    }
    
    private fun validateBrand(
        attestation: KeyMintAttestation,
        issues: MutableList<String>,
        warnings: MutableList<String>
    ) {
        attestation.brand?.let { attestationBrand ->
            val systemBrand = Build.BRAND
            val attestationStr = attestationBrand.decodeToString()
            if (attestationStr != systemBrand) {
                issues.add("Brand mismatch: attestation=$attestationStr, system=$systemBrand")
            }
        }
    }
    
    private fun validateDevice(
        attestation: KeyMintAttestation,
        issues: MutableList<String>,
        warnings: MutableList<String>
    ) {
        attestation.device?.let { attestationDevice ->
            val systemDevice = Build.DEVICE
            val attestationStr = attestationDevice.decodeToString()
            if (attestationStr != systemDevice) {
                issues.add("Device mismatch: attestation=$attestationStr, system=$systemDevice")
            }
        }
    }
    
    private fun validateProduct(
        attestation: KeyMintAttestation,
        issues: MutableList<String>,
        warnings: MutableList<String>
    ) {
        attestation.product?.let { attestationProduct ->
            val systemProduct = Build.PRODUCT
            val attestationStr = attestationProduct.decodeToString()
            if (attestationStr != systemProduct) {
                warnings.add("Product mismatch: attestation=$attestationStr, system=$systemProduct")
            }
        }
    }
    
    private fun validateModel(
        attestation: KeyMintAttestation,
        issues: MutableList<String>,
        warnings: MutableList<String>
    ) {
        attestation.model?.let { attestationModel ->
            val systemModel = Build.MODEL
            val attestationStr = attestationModel.decodeToString()
            if (attestationStr != systemModel) {
                issues.add("Model mismatch: attestation=$attestationStr, system=$systemModel")
            }
        }
    }
    
    private fun validateManufacturer(
        attestation: KeyMintAttestation,
        issues: MutableList<String>,
        warnings: MutableList<String>
    ) {
        attestation.manufacturer?.let { attestationManufacturer ->
            val systemManufacturer = Build.MANUFACTURER
            val attestationStr = attestationManufacturer.decodeToString()
            if (attestationStr != systemManufacturer) {
                warnings.add("Manufacturer mismatch: attestation=$attestationStr, system=$systemManufacturer")
            }
        }
    }
    
    private fun getSystemImei(): String? {
        return try {
            SystemProperties.get("ro.ril.oem.imei")
                ?: SystemProperties.get("persist.radio.imei")
                ?: SystemProperties.get("ro.ril.oem.imei1")
                ?: SystemProperties.get("ril.imei")
        } catch (e: Exception) {
            SystemLogger.debug("[$TAG] Could not read IMEI from system: ${e.message}")
            null
        }
    }
    
    private fun getSystemImei2(): String? {
        return try {
            SystemProperties.get("ro.ril.oem.imei2")
                ?: SystemProperties.get("persist.radio.imei2")
                ?: SystemProperties.get("ril.imei2")
        } catch (e: Exception) {
            null
        }
    }
    
    private fun getSystemSerial(): String? {
        return try {
            val serial = SystemProperties.get("ro.boot.serialno")
                ?: SystemProperties.get("ro.serialno")
            
            if (serial.isNullOrBlank()) {
                try {
                    Build.getSerial()
                } catch (e: SecurityException) {
                    null
                }
            } else {
                serial
            }
        } catch (e: Exception) {
            SystemLogger.debug("[$TAG] Could not read serial from system: ${e.message}")
            null
        }
    }
    
    fun logValidationResult(attestation: KeyMintAttestation) {
        val result = validateAttestationIdentifiers(attestation)
        if (!result.isValid) {
            SystemLogger.warning("[$TAG] Device identifier validation failed:\n${result.summary}")
        } else if (result.warnings.isNotEmpty()) {
            SystemLogger.debug("[$TAG] Device identifier validation passed with warnings:\n${result.summary}")
        } else {
            SystemLogger.verbose("[$TAG] Device identifier validation passed")
        }
    }
}
