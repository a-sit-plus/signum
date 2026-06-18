@file:OptIn(ExperimentalKotlinGradlePluginApi::class)

import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest
import org.jetbrains.kotlin.konan.target.HostManager

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.supreme", 30)
    mavenPublish(
        name = "Signum Supreme",
        description = "Kotlin Multiplatform Crypto Provider"
    )
    supreme = true
}

// The iOS simulator grants keychain access based on the `application-identifier` /
// `keychain-access-groups` entitlements *embedded in the Mach-O `__TEXT,__entitlements` section*
// (this is how Xcode signs simulator builds). Without them, keychain calls fail with
// -34018 (errSecMissingEntitlement). The same entitlements must NOT be attached via the code
// signature instead: launchd treats signature-embedded restricted entitlements as requiring a
// provisioning profile and rejects the spawn with a "Security policy issue" (code 163). We
// therefore inject them as a linker section on the simulator test binary only.
val iosTestAppIdentifier = "at.asitplus.signum.supreme.test"
val iosTestEntitlementsFile = layout.buildDirectory.file("tmp/iosSimTest.entitlements").get().asFile.apply {
    parentFile.mkdirs()
    writeText(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>application-identifier</key>
            <string>$iosTestAppIdentifier</string>
            <key>keychain-access-groups</key>
            <array>
                <string>$iosTestAppIdentifier</string>
            </array>
        </dict>
        </plist>
        """.trimIndent()
    )
}

kotlin {
    jvm()

    val iosTargets = if (disableAppleTargets) listOf() else listOf(iosArm64(), iosSimulatorArm64())
    // Adapted from https://github.com/openwallet-foundation/multipaz
    iosTargets.forEach { target ->
        val platform = when (target.name) {
            "iosArm64" -> "iphoneos"
            "iosSimulatorArm64" -> "iphonesimulator"
            else -> error("Unsupported target ${target.name}")
        }
        if (HostManager.hostIsMac) {
            target.compilations.getByName("main") {
                val cinterop by cinterops.creating {
                    definitionFile.set(file("$rootDir/cinterop/AESwift-$platform.def"))
                    includeDirs.headerFilterOnly("$rootDir/cinterop/build/Release-$platform/include")

                    val interopTask = tasks[interopProcessingTaskName]
                    interopTask.dependsOn(":cinterop:buildIphoneos")
                    interopTask.dependsOn(":cinterop:buildIphonesimulator")
                }

                target.binaries.all {
                    linkerOpts(
                        "-L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/${platform}/",
                        "-L$rootDir/cinterop/build/Release-${platform}",
                        "-lAESwift"
                    )
                }
            }

            // embed keychain entitlements into the simulator test binary so keychain-backed tests work
            if (platform == "iphonesimulator") {
                target.binaries.getTest(org.jetbrains.kotlin.gradle.plugin.mpp.NativeBuildType.DEBUG)
                    .linkerOpts("-sectcreate", "__TEXT", "__entitlements", iosTestEntitlementsFile.absolutePath)
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            api(project(":indispensable"))
            implementation(project(":internals"))
            implementation(coroutines())
            implementation(napier()) //TODO: modulator!
            implementation(libs.securerandom) //fix composite build
        }

        if(hasAndroidSdk()) androidMain.dependencies {
            implementation("androidx.biometric:biometric:1.2.0-alpha05")
        }

        commonTest.dependencies {
            implementation("at.asitplus:kmmresult-test:${AspVersions.kmmresult}")
        }

        jvmTest.dependencies {
            implementation("com.lambdaworks:scrypt:1.4.0")
            gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?:implementation(project(":internals-test"))
        }
        if (!disableAppleTargets) iosMain {
            if (!HostManager.hostIsMac) kotlin.srcDir("src/iosMain/stubbed")
        }
    }
}

//Task alias for github action globbing
tasks.register("assembleSignumSupremeXCFramework") {
    dependsOn("assembleSupremeXCFramework")
}

//work no stand-alone needs manual booting and we manually shutdown
val shutdownIosSimulator by tasks.registering {
    doLast {
        providers.exec {
            commandLine("xcrun", "simctl", "shutdown", "iPhone 16")
            isIgnoreExitValue = true
        }.result.get()
    }
}

//remove --standalone from simulator to cast out demons. but then we need to boot manually
tasks.withType<KotlinNativeSimulatorTest>().configureEach {
    standalone.set(false)

    doFirst {
        providers.exec {
            commandLine("xcrun", "simctl", "boot", device.get())
            isIgnoreExitValue = true
        }.result.get()

        providers.exec {
            commandLine("xcrun", "simctl", "bootstatus", device.get(), "-b")
        }.result.get().assertNormalExitValue()
    }

    finalizedBy(shutdownIosSimulator)
}

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


