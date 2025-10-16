import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl


plugins {
    id("com.android.kotlin.multiplatform.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("signing")
    id("at.asitplus.gradle.conventions")
    id("de.infix.testBalloon")
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.indispensable.asn1")
}

val artifactVersion: String by extra
version = artifactVersion


kotlin {
    jvm()
    macosArm64()
    macosX64()
    tvosArm64()
    tvosX64()
    tvosSimulatorArm64()
    iosX64()
    iosArm64()
    iosSimulatorArm64()
    watchosSimulatorArm64()
    watchosX64()
    watchosArm32()
    watchosArm64()
    //we cannot currently test this, so it is only enabled for publishing
    gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }
    tvosSimulatorArm64()
    tvosX64()
    tvosArm64()
    androidNativeX64()
    androidNativeX86()
    androidNativeArm32()
    androidNativeArm64()

    listOf(
        js().apply { browser { testTask { enabled = false } } },
        @OptIn(ExperimentalWasmDsl::class)
        wasmJs().apply { browser { testTask { enabled = false } } },
       // wasmWasi()
    ).forEach {
        it.nodejs()
    }

    linuxX64()
    linuxArm64()
    mingwX64()

    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
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

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/signum/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("Indispensable ASN.1")
                description.set("Kotlin Multiplatform ASN.1 Engine")
                url.set("https://github.com/a-sit-plus/signum")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("JesusMcCloud")
                        name.set("Bernd Prünster")
                        email.set("bernd.pruenster@a-sit.at")
                    }
                    developer {
                        id.set("iaik-jheher")
                        name.set("Jakob Heher")
                        email.set("jakob.heher@tugraz.at")
                    }
                    developer {
                        id.set("nodh")
                        name.set("Christian Kollmann")
                        email.set("christian.kollmann@a-sit.at")
                    }
                    developer {
                        id.set("n0900")
                        name.set("Simon Müller")
                        email.set("simon.mueller@a-sit.at")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:a-sit-plus/signum.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/signum.git")
                    url.set("https://github.com/a-sit-plus/signum")
                }
            }
        }
    }
    repositories {
        mavenLocal {
            signing.isRequired = false
        }
        maven {
            url = uri(layout.projectDirectory.dir("..").dir("repo"))
            name = "local"
            signing.isRequired = false
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}
