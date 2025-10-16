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

val artifactVersion: String by extra
version = artifactVersion


kotlin {
    indispensableTargets()
    //we cannot currently test this, so it is only enabled for publishing
    project.gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }

    sourceSets {
        all {
            languageSettings.enableLanguageFeature("ContextParameters")
        }

        commonMain {
            kotlin.srcDir(
                project.layout.projectDirectory.dir("generated")
                    .dir("commonMain").dir("kotlin")
            )

            dependencies {
                api(libs.kotlinx.io.core)
                api(kmmresult())
                api(serialization("json"))
                api(datetime())
            }
        }
        commonTest {
            dependencies {
                implementation(project(":indispensable"))
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
    "IndispensableAsn1",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult()

)
