import at.asitplus.gradle.datetime
import at.asitplus.gradle.exportIosFramework
import at.asitplus.gradle.kmmresult
import at.asitplus.gradle.napier
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

        commonMain {
            dependencies {
                api(project(":indispensable"))
                api(serialization("cbor"))
                implementation(napier())
                implementation(libs.multibase)
                implementation(libs.bignum) //Intellij bug work-around
            }
        }
    }
}

exportIosFramework(
    "IndispensableCosef",
    transitiveExports=false,
    serialization("cbor"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    libs.bignum
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
                name.set("Indispensable COSEF")
                description.set("Kotlin Multiplatform Crypto Library - COSE Addons")
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
