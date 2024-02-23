import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.datetime
import at.asitplus.gradle.exportIosFramework
import at.asitplus.gradle.kmmresult
import at.asitplus.gradle.kotest
import at.asitplus.gradle.serialization
import at.asitplus.gradle.setupDokka

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
version = artifactVersion

kotlin {
    jvm()
    iosArm64()
    iosSimulatorArm64()
    iosX64()
    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
        }

        val commonMain by getting {
            dependencies {
                api(kmmresult())
                api(serialization("json"))
                api(datetime())
                implementation(libs.base16)
                implementation(libs.base64)
                implementation(libs.bignum)
            }
        }

        val commonTest by getting {
            dependencies {
                implementation(kotest("property"))
                implementation(kotlin("reflect"))
            }
        }

        val jvmMain by getting {
            dependencies {
                api(bouncycastle("bcpkix"))
            }
        }

        val jvmTest by getting
    }
}
exportIosFramework("KmpCrypto", serialization("json"), datetime(), kmmresult())

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/kmp-crypto/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("KMP Crypto Datatypes")
                description.set("Kotlin Multiplatform Crypto Core Library, Datatypes and ASN.1 Perser+Encoder")
                url.set("https://github.com/a-sit-plus/kmp-crypto")
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
                        id.set("nodh")
                        name.set("Christian Kollmann")
                        email.set("christian.kollmann@a-sit.at")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:a-sit-plus/kmp-crypto.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/kmp-crypto.git")
                    url.set("https://github.com/a-sit-plus/kmp-crypto")
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
