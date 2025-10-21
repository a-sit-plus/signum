package at.asitplus.gradle

import com.android.build.api.dsl.androidLibrary
import com.android.build.api.variant.KotlinMultiplatformAndroidComponentsExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.StopExecutionException
import org.gradle.api.tasks.testing.Test
import org.gradle.internal.os.OperatingSystem
import org.gradle.kotlin.dsl.*
import org.gradle.plugins.signing.SigningExtension
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.Family
import java.io.ByteArrayOutputStream

/**
 * Gradle convention plugin for Signum. Handles:
 * * plugin application
 * * setting artefact coordinates and version
 * * maven publish
 * * hacks to make swift interop ACTUALLY work
 * * android wiring
 * * large test heap
 * * setting up all targets
 * * silencing warnings on non-apple system about unbuildable targets
 */
class SignumConventionsPlugin : Plugin<Project> {
    override fun apply(target: Project) = with(target) {
        logger.info("Signum Conventions Plugin applied to project: ${'$'}{target.path}")
        pluginManager.apply("org.jetbrains.kotlin.multiplatform")
        pluginManager.apply("org.jetbrains.kotlin.plugin.serialization")
        pluginManager.apply("com.android.kotlin.multiplatform.library")
        pluginManager.apply("signing")
        pluginManager.apply("at.asitplus.gradle.conventions")
        pluginManager.apply("de.infix.testBalloon")
    }
}

class SignumConventionsExtension(private val project: Project) {
    init {
        val indispensableVersion: String by project.extra
        project.version = indispensableVersion
        //if we do this properly, cinterop (swift-klib) blows up, so we hack!
        project.afterEvaluate {
            tasks.withType<Test>().configureEach {
                maxHeapSize = "4G"
            }

            if (supreme) {
                //we still need this. Something's fishy with x64 test targets.
                // HOWEVER: we never want to test on X64 anyway, and it has no impact on
                // producing valid artefacts, and I have spent enough time failing to find the root cause
                tasks.configureEach {
                    if (name == "linkDebugTestIosX64") {
                        enabled = false
                    }
                    if (name == "iosX64Test") {
                        enabled = false
                    }
                }
            }
        }
        project.silence()
        project.workaroundAppleToolchainBugs()

        project.extensions.getByType<KotlinMultiplatformExtension>().apply {
            compilerOptions.freeCompilerArgs.add("-Xexpect-actual-classes")
            sourceSets.whenObjectAdded {
                languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
            }
        }

        project.extensions.getByType<KotlinMultiplatformAndroidComponentsExtension>().apply {
            onVariants { v ->
                // Configure the instrumented-test APK only
                v.androidTest?.manifestPlaceholders?.put("testLargeHeap", "true")
            }
        }
    }

    var supreme: Boolean = false
        get() {
            return field
        }
        set(value) {
            if (!value) {
                val indispensableVersion: String by project.extra
                project.version = indispensableVersion
            } else {
                val supremeVersion: String by project.extra
                project.version = supremeVersion
            }
            field = value

        }

    fun mavenPublish(name: String, description: String) = project.afterEvaluate {
        val javadocJar = setupDokka(
            baseUrl = "https://github.com/a-sit-plus/signum/tree/main/",
            multiModuleDoc = true
        )
        extensions.getByType<PublishingExtension>().apply {

            publications {
                withType<MavenPublication> {
                    if (this.name != "relocation") artifact(javadocJar)
                    pom {
                        this.name.set(name)
                        this.description.set(description)
                        url.set("https://github.com/a-sit-plus/signum")
                        licenses {
                            license {
                                this.name.set("The Apache License, Version 2.0")
                                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                            }
                        }
                        developers {
                            developer {
                                id.set("JesusMcCloud")
                                this.name.set("Bernd Prünster")
                                email.set("bernd.pruenster@a-sit.at")
                            }
                            developer {
                                id.set("iaik-jheher")
                                this.name.set("Jakob Heher")
                                email.set("jakob.heher@tugraz.at")
                            }
                            developer {
                                id.set("nodh")
                                this.name.set("Christian Kollmann")
                                email.set("christian.kollmann@a-sit.at")
                            }
                            developer {
                                id.set("n0900")
                                this.name.set("Simon Müller")
                                email.set("simon.mueller@a-sit.at")
                            }
                        }
                        scm {
                            connection.set("scm:git:git@github.com:a-sit-plus/signum.git")
                            developerConnection.set("scm:git:git@github.com:a-sit-plus/signum.git")
                            url.set("https://github.com/a-sit-plus/signum")
                        }
                    }
                }
            }
            repositories {
                mavenLocal {
                    extensions.getByType<SigningExtension>().apply {
                        isRequired = false
                    }
                }
                maven {
                    url = uri(layout.projectDirectory.dir("..").dir("repo"))
                    this.name = "local"
                    extensions.getByType<SigningExtension>().apply {
                        isRequired = false
                    }
                }
            }
        }

        extensions.getByType<SigningExtension>().apply {
            {
                val signingKeyId: String? by project
                val signingKey: String? by project
                val signingPassword: String? by project
                useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
                sign(extensions.getByType<PublishingExtension>().publications)
            }

        }
    }


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

//we only require this for when swift-klib is used, so we let the extension trigger it
// this is a target-agnostic version of the fix described in https://github.com/ttypic/swift-klib-plugin/issues/35
private fun Project.workaroundAppleToolchainBugs() = extensions.findByName("swiftklib")?.let {

    /*help the linker (yes, this is absolutely bonkers!)*/
    if (OperatingSystem.current() == OperatingSystem.MAC_OS) {
        val devDir = System.getenv("DEVELOPER_DIR")?.ifEmpty { null }.let {
            if (it == null) {
                val output = ByteArrayOutputStream()
                exec {
                    commandLine("xcode-select", "-p")
                    standardOutput = output
                }
                output.toString().trim()
            } else it
        }

        logger.lifecycle("  DEV DIR points to $devDir")

        val swiftLib = "$devDir/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/"

        extensions.getByType<KotlinMultiplatformExtension>().targets.withType<KotlinNativeTarget>()
            .configureEach {
                val sub = when (konanTarget.family) {
                    Family.IOS ->
                        if (konanTarget.name.contains("SIMULATOR", true)) "iphonesimulator" else "iphoneos"

                    Family.OSX -> "macosx"
                    Family.TVOS ->
                        if (konanTarget.name.contains("SIMULATOR", true)) "appletvsimulator" else "appletvos"

                    Family.WATCHOS ->
                        if (konanTarget.name.contains("SIMULATOR", true)) "watchsimulator" else "watchos"

                    else -> throw StopExecutionException("Konan target ${konanTarget.name} is not recognized")
                }

                logger.lifecycle("  KONAN target is ${konanTarget.name} which resolves to $sub")
                binaries.all {
                    linkerOpts(
                        "-L${swiftLib}$sub"
                    )
                }
            }
    }
}

private fun Project.silence() {
    val kmp = extensions.getByType<KotlinMultiplatformExtension>()
    val tbr = mutableSetOf<KotlinTarget>()
    kmp.targets.whenObjectAdded {
        val buildableTargets = kmp.getBuildableTargets()
        if (!buildableTargets.contains(this)) {
            tasks.findByName("checkKotlinGradlePluginConfigurationErrors")?.enabled = false
            tbr += this
            logger.warn(">>>> Target $this is not buildable on the current host <<<<")
        }
    }
    afterEvaluate {
        kmp.targets.removeAll(tbr)
    }

}

private fun KotlinMultiplatformExtension.getBuildableTargets() =
    targets.filter { target ->
        when {
            // Non-native targets are always buildable
            target.platformType != org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType.native -> true
            else -> runCatching {
                val konanTarget = (target as? KotlinNativeTarget)
                konanTarget?.publishable == true
            }.getOrElse { false }
        }
    }


fun KotlinMultiplatformExtension.indispensableTargets() {
    jvm()
    macosArm64()
    macosX64()
    tvosArm64()
    tvosX64()
    tvosSimulatorArm64()
    iosX64()
    iosArm64()
    iosSimulatorArm64()
    watchosSimulatorArm64()
    watchosX64()
    watchosArm32()
    watchosArm64()
    tvosSimulatorArm64()
    tvosX64()
    tvosArm64()
    androidNativeX64()
    androidNativeX86()
    androidNativeArm32()
    androidNativeArm64()

    listOf(
        js().apply { browser { testTask { enabled = false } } },
        @OptIn(ExperimentalWasmDsl::class)
        wasmJs().apply { browser { testTask { enabled = false } } },
        // wasmWasi()
    ).forEach {
        it.nodejs()
    }

    linuxX64()
    linuxArm64()
    mingwX64()
}

