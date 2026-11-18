import at.asitplus.gradle.*

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.indispensable.pkix")
    mavenPublish(
        name = "Indispensable PKIX",
        description = "Kotlin Multiplatform Crypto Library - Typed X.509 PKIX extensions and attributes"
    )
}


kotlin {
    indispensableTargets()

    sourceSets {
        commonMain {
            dependencies {
                api(project(":indispensable"))
                implementation(project(":internals"))
                implementation(libs.bignum) //Intellij bug work-around
                api(libs.cidre)
                api(libs.urikmp)
            }
        }

        jvmTest {
            dependencies {
                implementation(project(":supreme"))
                gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?:implementation(project(":internals-test"))
            }
        }
    }
}

exportXCFramework(
    "IndispensablePkix",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    libs.awesn1.crypto,
    libs.awesn1.oids,
    libs.bignum,
    libs.cidre,
    libs.urikmp
)
