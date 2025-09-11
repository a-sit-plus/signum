import at.asitplus.gradle.*


plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.indispensable.asn1")
    mavenPublish(
        name = "Indispensable ASN.1",
        description = "Kotlin Multiplatform ASN.1 Engine"
    )
}

kotlin {
    indispensableTargets()
    //we cannot currently test this, so it is only enabled for publishing
    project.gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(project(":internals"))
                api(libs.kotlinx.io.core)
                api(kmmresult())
                api(serialization("json"))
                api(datetime())
            }
        }
        commonTest {
            dependencies {
                implementation(project(":indispensable"))
            }
        }
    }
}

exportXCFramework(
    "IndispensableAsn1",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult()

)
