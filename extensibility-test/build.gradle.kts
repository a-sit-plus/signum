import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.plugin.mpp.NativeBuildType
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest
import org.jetbrains.kotlin.konan.target.HostManager

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.extensibility.test", 30)
}

kotlin {
    jvm()
    if (!disableAppleTargets && HostManager.hostIsMac) {
        iosArm64()
        iosSimulatorArm64().binaries.getTest(NativeBuildType.DEBUG).linkerOpts(
            "-sectcreate", "__TEXT", "__entitlements",
            layout.projectDirectory.file("src/iosTest/test.entitlements").asFile.absolutePath,
            "-sectcreate", "__TEXT", "__info_plist",
            layout.projectDirectory.file("src/iosTest/Info.plist").asFile.absolutePath,
        )
    }

    sourceSets {
        commonTest.dependencies {
            implementation(project(":supreme"))
            implementation(project(":indispensable-pkix"))
        }
        jvmTest.dependencies {
            implementation(project(":internals-test"))
        }
    }
}

// As in Supreme's iOS tests, the simulator must be booted for Keychain calls.
tasks.withType<KotlinNativeSimulatorTest>().configureEach {
    standalone.set(false)
    doFirst {
        providers.exec {
            commandLine("xcrun", "simctl", "bootstatus", device.get(), "-b")
        }.result.get().assertNormalExitValue()
    }
}
