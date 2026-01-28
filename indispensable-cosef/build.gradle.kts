import at.asitplus.gradle.*

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.indispensable.cosef")
    mavenPublish(
        name = "Indispensable COSEF",
        description = "Kotlin Multiplatform Crypto Library - COSE Addons"
    )
}

kotlin {
    indispensableTargets()

    sourceSets {
        commonMain {
            dependencies {
                api(project(":indispensable"))
                implementation(project(":internals"))
                api(serialization("cbor"))
                implementation(libs.multibase)
                implementation(libs.bignum) //Intellij bug work-around
            }
        }
        jvmTest.dependencies {
            gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?:implementation(project(":internals-test"))
        }
    }
}
exportXCFramework(
    "IndispensableCosef",
    transitiveExports = false,
    static = false,
    serialization("cbor"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    project(":indispensable-asn1"),
    libs.bignum

)
