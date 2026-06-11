import at.asitplus.gradle.*
import at.asitplus.gradle.modulator.carrier


plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.cosef.supreme")
    mavenPublish(
        name = "COSEF Supreme",
        description = "Kotlin Multiplatform Crypto Library - COSE Supreme"
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
                carrier(project(":indispensable-cosef"))
            }
        }
        jvmTest.dependencies {
            gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?:implementation(project(":internals-test"))
        }
    }
}
exportXCFramework(
    "CosefSupreme",
    transitiveExports = false,
    static = false,
    serialization("cbor"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    project(":indispensable-asn1"),
    project(":indispensable-cosef"),
    project(":supreme"),
    libs.bignum

)
