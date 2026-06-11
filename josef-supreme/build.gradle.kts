import at.asitplus.gradle.*
import at.asitplus.gradle.modulator.carrier


plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.josef.supreme")
    mavenPublish(
        name = "JOSEF Supreme",
        description = "Kotlin Multiplatform Crypto Library - JOSE Supreme"
    )
    supreme= true
}

kotlin {
    jvm()

    if (disableAppleTargets) listOf() else listOf(iosArm64(), iosSimulatorArm64())


    sourceSets {
        commonMain {
            dependencies {
                carrier(project(":supreme"))
                carrier(project(":indispensable-josef"))
            }
        }
        jvmTest.dependencies {
            gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?:implementation(project(":internals-test"))
        }
    }
}
exportXCFramework(
    "JosefSupreme",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    project(":indispensable-asn1"),
    project(":indispensable-josef"),
    project(":supreme"),
    libs.bignum

)
