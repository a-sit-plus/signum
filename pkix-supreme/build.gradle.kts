@file:OptIn(ExperimentalKotlinGradlePluginApi::class)

import at.asitplus.gradle.*
import at.asitplus.gradle.modulator.carrier
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest
import org.jetbrains.kotlin.konan.target.HostManager

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.pkix.supreme",30)
    mavenPublish(
        name = "PKIX Supreme",
        description = "Kotlin Multiplatform RFC 5280 certificate path validation and system trust store"
    )
    supreme = true
}

kotlin {
    jvm()

    val iosTargets = if (disableAppleTargets) listOf() else listOf(iosArm64(), iosSimulatorArm64())

    sourceSets {
        commonMain.dependencies {
            // BundledTrustStore + its embedded roots now live in indispensable-pkix (always available);
            // systemTrustStore actuals here only wrap the live OS store.
            carrier(project(":supreme"))
            carrier(project(":indispensable-pkix"))
            implementation(project(":internals"))
            implementation(coroutines())
        }

        commonTest.dependencies {
            implementation("at.asitplus:kmmresult-test:${AspVersions.kmmresult}")
        }

        jvmTest.dependencies {
            gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?:implementation(project(":internals-test"))
        }

        if (!disableAppleTargets) iosMain {
            if (!HostManager.hostIsMac) kotlin.srcDir("src/iosMain/stubbed")
        }
    }
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
    "PkixSupreme",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    project(":indispensable-pkix"),
    project(":supreme"),
    libs.bignum
)

