import at.asitplus.gradle.*

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {

    android("at.asitplus.signum.indispensable.internals")
    mavenPublish(
        name = "Indispensable Internals",
        description = "Kotlin Multiplatform Crypto Library, Internal Shared Helpers"
    )
}


kotlin {
    indispensableTargets()
    project.gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }

    sourceSets {
        commonTest {
            dependencies {
                implementation(libs.kotlinx.io.core)
            }
        }
    }
}

exportXCFramework(
    "Internals",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult()

)

