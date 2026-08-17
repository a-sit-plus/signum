package at.asitplus.signum.supreme.os

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyProperties
import androidx.test.platform.app.InstrumentationRegistry
import at.asitplus.signum.supreme.dsl.DISCOURAGED
import at.asitplus.signum.supreme.dsl.FeaturePreference
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.dsl.REQUIRED
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.engine.runBlocking
import io.kotest.matchers.shouldBe
import java.util.*

private data class PreferenceCase(val name: String, val value: FeaturePreference)

private val preferenceCases = listOf(
    PreferenceCase("REQUIRED", REQUIRED),
    PreferenceCase("PREFERRED", PREFERRED),
    PreferenceCase("DISCOURAGED", DISCOURAGED),
)

//fuzzy matching
internal val isEmulator: Boolean
    get() = Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.contains("emulator", ignoreCase = true) ||
            Build.MODEL.contains("Emulator", ignoreCase = true) ||
            Build.PRODUCT.contains("sdk", ignoreCase = true) ||
            Build.HARDWARE == "goldfish" || Build.HARDWARE == "ranchu"

/**
 * Run the complete suite on all three Android 12+ targets; each target covers a different branch:
 *
 * - Physical Pixel with StrongBox: REQUIRED succeeds and PREFERRED selects StrongBox.
 * - Physical Nothing phone with TEE only: REQUIRED fails and PREFERRED falls back to TEE.
 * - Emulator without hardware-backed Keystore: REQUIRED hardware fails and PREFERRED falls back to software.
 *
 * `./gradlew :supreme:connectedAndroidDeviceTest` runs connected phones.
 * `./gradlew :supreme:pixelAVDAndroidDeviceTest` runs the configured API 35 emulator.
 *
 * The suite derives expectations from a probe key's actual security level rather than device model names, so run
 * all nine cases on every target. Exact security-level assertions require API 31's `KeyInfo.securityLevel`.
 */
val AndroidKeyStorePreferenceTests by matrixSuite {
    "emu=$isEmulator" - {
        //no proper data tests to keep names short (android is has limited test name length)
        preferenceCases.forEach { hardwareBacking ->
            preferenceCases.forEach { strongBox ->
                "HW=${hardwareBacking.name}, SB=${strongBox.name}" - {
                    check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        "StrongBox preference tests require Android 12 (API 31) or newer"
                    }

                    val packageManager = InstrumentationRegistry.getInstrumentation().targetContext.packageManager
                    val hasStrongBox = !isEmulator &&
                            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
                    val probeAlias = "probe-${UUID.randomUUID()}"
                    val defaultSecurityLevel = runBlocking {
                        try {
                            AndroidKeyStoreProvider.createSigningKey(probeAlias).getOrThrow().securityLevel
                        } finally {
                            AndroidKeyStoreProvider.deleteSigningKey(probeAlias).getOrThrow()
                        }
                    }
                    val expectedSecurityLevel = when {
                        isEmulator -> KeyProperties.SECURITY_LEVEL_SOFTWARE
                        strongBox.value != DISCOURAGED && hasStrongBox -> KeyProperties.SECURITY_LEVEL_STRONGBOX
                        else -> defaultSecurityLevel
                    }
                    val expectedHardwareBacking =
                        expectedSecurityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                                expectedSecurityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                                expectedSecurityLevel == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
                    val shouldSucceed =
                        (strongBox.value != REQUIRED || hasStrongBox) &&
                                (hardwareBacking.value != REQUIRED || expectedHardwareBacking)
                    val alias = "signum-preferences-${UUID.randomUUID()}"

                    ("device=${Build.MANUFACTURER}" +
                            "SB=$hasStrongBox, default seclevel=$defaultSecurityLevel, ") - {
                        try {
                            val result = runBlocking {
                                AndroidKeyStoreProvider.createSigningKey(alias) {
                                    hardware {
                                        backing = hardwareBacking.value
                                        this.strongBox = strongBox.value
                                    }
                                }
                            }
                            "should succeed=${shouldSucceed}" { result.isSuccess shouldBe shouldSucceed }
                            if (!shouldSucceed) {
                                "A failed REQUIRED request must not leave a key behind" {
                                    AndroidKeyStoreProvider.getSignerForKey(alias).isFailure shouldBe true
                                }
                            }
                            result.getOrNull()?.let { signer ->
                                "Sec LVL= ${signer.securityLevel}" {
                                    signer.securityLevel shouldBe expectedSecurityLevel
                                    signer.isStrongBoxBacked shouldBe
                                            (expectedSecurityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX)
                                }
                            }
                        } finally {
                            runBlocking { AndroidKeyStoreProvider.deleteSigningKey(alias).getOrThrow() }
                        }
                    }
                }
            }
        }
    }
}
