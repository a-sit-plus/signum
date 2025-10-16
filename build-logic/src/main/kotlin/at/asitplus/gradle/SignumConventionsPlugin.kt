package at.asitplus.gradle

import com.android.build.api.dsl.androidLibrary
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.invoke
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

/**
 * Gradle convention plugin for Signum
 */
class SignumConventionsPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        // Intentionally left blank for skeleton setup.
        // Add common configuration and plugin applications here in the future.
        target.logger.info("SignumConventionsPlugin applied as skeleton to project: ${'$'}{target.path}")
    }
}

class SignumConventionsExtension(private val project: Project) {


    fun android(namespace: String, minSdkOverride: Int? = null) {
        project.extensions.getByType<KotlinMultiplatformExtension>().apply {
            androidLibrary {

                this.namespace = namespace
                minSdkOverride?.let {
                    project.logger.lifecycle("  \u001b[7m\u001b[1m" + "Overriding Android defaultConfig minSDK to $minSdkOverride for project ${project.name}" + "\u001b[0m")
                    minSdk = it
                }
                withDeviceTestBuilder {
                    sourceSetTreeName = "test"
                }.configure {
                    instrumentationRunnerArguments["timeout_msec"] = "2400000"
                    managedDevices {
                        localDevices {
                            create("pixelAVD").apply {
                                device = "Pixel 4"
                                apiLevel = 35
                                systemImageSource = "aosp-atd"
                            }
                        }
                    }
                }
                packaging {
                    listOf(
                        "org/bouncycastle/pqc/crypto/picnic/lowmcL5.bin.properties",
                        "org/bouncycastle/pqc/crypto/picnic/lowmcL3.bin.properties",
                        "org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties",
                        "org/bouncycastle/x509/CertPathReviewerMessages_de.properties",
                        "org/bouncycastle/x509/CertPathReviewerMessages.properties",
                        "org/bouncycastle/pkix/CertPathReviewerMessages_de.properties",
                        "org/bouncycastle/pkix/CertPathReviewerMessages.properties",
                        "/META-INF/{AL2.0,LGPL2.1}",
                        "win32-x86-64/attach_hotspot_windows.dll",
                        "win32-x86/attach_hotspot_windows.dll",
                        "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                        "META-INF/licenses/*",
                        //noinspection WrongGradleMethod
                    ).forEach { resources.excludes.add(it) }
                }
            }
        }
    }
}

fun Project.signumConventions(init: SignumConventionsExtension.() -> Unit) {
    SignumConventionsExtension(this).init()

}
