import at.asitplus.gradle.AspVersions
import at.asitplus.gradle.coroutines
import at.asitplus.gradle.napier
import at.asitplus.gradle.setupDokka
import com.android.build.api.dsl.androidLibrary
import org.gradle.internal.os.OperatingSystem
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.Family
import java.io.ByteArrayOutputStream

plugins {
    id("com.android.kotlin.multiplatform.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("signing")
    id("at.asitplus.gradle.conventions")
    id("de.infix.testBalloon")
    id("io.github.ttypic.swiftklib") version "0.6.4"
}

val supremeVersion: String by extra
version = supremeVersion


afterEvaluate {
//we only ever test on the simulator, so these two should never be enabled in the first place
//however, kotest ksp wiring messes this up and forces us to build for something we never intend, and this breaks linking.
//hence, we disable those
    tasks.configureEach {
        if (name == "linkDebugTestIosX64") {
            enabled = false
        }
        if (name == "iosX64Test") {
            enabled = false
        }
    }
}

androidComponents {
    // Runs for every build variant of your library
    onVariants { v ->
        // Configure the instrumented-test APK only
        v.androidTest?.manifestPlaceholders?.put("testLargeHeap", "true")
    }
}

kotlin {
    compilerOptions.freeCompilerArgs.add("-Xexpect-actual-classes")
    jvm()
    androidLibrary {
        namespace = "at.asitplus.signum.supreme"
        logger.lifecycle("  \u001b[7m\u001b[1m" + "Overriding Android defaultConfig minSDK to 30 for project Supreme" + "\u001b[0m")
        minSdk = 30 //override
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunnerArguments["timeout_msec"] = "5000"
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


    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.compilations {
            val main by getting { cinterops.create("AESwift") }
        }
    }


    sourceSets {
        commonMain.dependencies {
            api(project(":indispensable"))
            implementation(project(":internals"))
            implementation(coroutines())
            implementation(napier())
            implementation(libs.securerandom) //fix composite build
        }

        androidMain.dependencies {
            implementation("androidx.biometric:biometric:1.2.0-alpha05")
        }

        commonTest.dependencies {
            implementation("at.asitplus:kmmresult-test:${AspVersions.kmmresult}")
            implementation("de.infix.testBalloon:testBalloon-framework-core:${AspVersions.testballoon}")
        }

        jvmTest.dependencies {
            implementation("com.lambdaworks:scrypt:1.4.0")
        }

        getByName("androidDeviceTest").dependencies {
            implementation(libs.runner)
            implementation("de.infix.testBalloon:testBalloon-framework-core:${AspVersions.testballoon}")
        }
    }
}


swiftklib {
    create("AESwift") {
        path = file("src/iosMain/swift")
        //Can't hide this in the iOS sources to consumers and using a discrete module is overkill -> so add "internal" to the package
        packageName("at.asitplus.signum.supreme.symmetric.internal.ios")
        minIos = 15
    }
}

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/signum/tree/main/",
    multiModuleDoc = true
)

repositories {
    maven("https://repo1.maven.org/maven2")
}

tasks.withType<Test>().configureEach {
    maxHeapSize = "4G"
}

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("Signum Supreme")
                description.set("Kotlin Multiplatform Crypto Provider")
                url.set("https://github.com/a-sit-plus/signum")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("JesusMcCloud")
                        name.set("Bernd Prünster")
                        email.set("bernd.pruenster@a-sit.at")
                    }
                    developer {
                        id.set("iaik-jheher")
                        name.set("Jakob Heher")
                        email.set("jakob.heher@tugraz.at")
                    }
                    developer {
                        id.set("nodh")
                        name.set("Christian Kollmann")
                        email.set("christian.kollmann@a-sit.at")
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
            signing.isRequired = false
        }
        maven {
            url = uri(layout.projectDirectory.dir("..").dir("repo"))
            name = "local"
            signing.isRequired = false
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}


/*
exportXCFramework(
    "SignumSupreme",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    project(":indispensable-asn1"),
    libs.bignum
)
*/


/*help the linker (yes, this is absolutely bonkers!)*/
if (OperatingSystem.current() == OperatingSystem.MAC_OS) {
    val devDir = System.getenv("DEVELOPER_DIR")?.ifEmpty { null }.let {
        if (it == null) {
            val output = ByteArrayOutputStream()
            project.exec {
                commandLine("xcode-select", "-p")
                standardOutput = output
            }
            output.toString().trim()
        } else it
    }

    logger.lifecycle("  DEV DIR points to $devDir")

    val swiftLib = "$devDir/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/"

    kotlin.targets.withType<KotlinNativeTarget>()
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
                    "-L${swiftLib}$sub",
                    "-L/usr/lib/swift"
                )
            }
        }
}