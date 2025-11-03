@file:OptIn(ExperimentalKotlinGradlePluginApi::class)

import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
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

kotlin {
    jvm()

    val iosTargets = listOf(iosX64(), iosArm64(), iosSimulatorArm64())
    // Adapted from https://github.com/openwallet-foundation/multipaz
    iosTargets.forEach { target ->
        val platform = when (target.name) {
            "iosX64" -> "iphonesimulator"
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

        androidMain.dependencies {
            implementation("androidx.biometric:biometric:1.2.0-alpha05")
        }

        commonTest.dependencies {
            implementation("at.asitplus:kmmresult-test:${AspVersions.kmmresult}")
        }

        jvmTest.dependencies {
            implementation("com.lambdaworks:scrypt:1.4.0")
        }
    }
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


