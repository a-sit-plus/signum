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

        commonTest {
            dependencies {
                implementation("de.infix.testBalloon:testBalloon-framework-core:${AspVersions.testballoon}")
            }
        }

        getByName("androidDeviceTest").dependencies {
            implementation(libs.runner)
            implementation("de.infix.testBalloon:testBalloon-framework-core:${AspVersions.testballoon}")
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
