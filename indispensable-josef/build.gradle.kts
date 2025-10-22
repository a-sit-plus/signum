import at.asitplus.gradle.*

plugins {
    id("at.asitplus.signum.buildlogic")
}


signumConventions {
    android("at.asitplus.signum.indispensable.josef")
    mavenPublish(
        name = "Indispensable JOSEF",
        description = "Kotlin Multiplatform Crypto Library - JOSE Addons"
    )
}


kotlin {
    indispensableTargets()

    sourceSets {
        commonMain {
            dependencies {
                api(project(":indispensable"))
                implementation(project(":internals"))
                api(libs.multibase)
                implementation(libs.bignum) //Intellij bug work-around
            }
        }

        jvmTest {
            dependencies {
                implementation(libs.jose)
                implementation(project(":supreme"))
            }

        }
    }
}

val disableAppleTargets by envExtra
if ("true" != disableAppleTargets) exportXCFramework(
    "IndispensableJosef",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    project(":indispensable-asn1"),
    libs.bignum

)
