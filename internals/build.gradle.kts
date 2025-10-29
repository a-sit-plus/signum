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
    watchosDeviceArm64()

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

