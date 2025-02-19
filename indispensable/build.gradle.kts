import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl


buildscript {
    dependencies {
        classpath(libs.kotlinpoet)
    }
}

plugins {
    id("com.android.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
version = artifactVersion


private val Pair<*, String?>.comment: String? get() = this.second
private val Pair<String, *>.oid: String? get() = this.first

kotlin {
    androidTarget { publishLibraryVariants("release") }
    jvm()
    macosArm64()
    macosX64()
    tvosArm64()
    tvosX64()
    tvosSimulatorArm64()
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    listOf(
        js(IR).apply { browser { testTask { enabled = false } } },
        @OptIn(ExperimentalWasmDsl::class)
        wasmJs().apply { browser { testTask { enabled = false } } }
    ).forEach {
        it.nodejs()
    }

    linuxX64()
    linuxArm64()
    mingwX64()

    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
        }

        commonMain.dependencies {
            api(project(":indispensable-asn1"))
            api(libs.multibase)
            api(libs.bignum)
            implementation(project(":internals"))
        }


        commonTest {
            dependencies {
                implementation(kotest("property"))
            }
        }

        //TODO: figure out a clean way in conventions to already access androidJvmMain here
        androidMain {
            dependencies {
                api(bouncycastle("bcpkix"))
                api(coroutines("jvm"))
            }
        }
        jvmMain {
            dependencies {
                api(bouncycastle("bcpkix"))
                api(coroutines("jvm"))
            }
        }

    }
}

exportXCFramework(
    "Indispensable",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":indispensable-asn1"),
    libs.bignum
)

android {
    namespace = "at.asitplus.signum.indispensable"
    packaging {
        listOf(
            "org/bouncycastle/pqc/crypto/picnic/lowmcL5.bin.properties",
            "org/bouncycastle/pqc/crypto/picnic/lowmcL3.bin.properties",
            "org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties",
            "org/bouncycastle/x509/CertPathReviewerMessages_de.properties",
            "org/bouncycastle/x509/CertPathReviewerMessages.properties",
            "org/bouncycastle/pkix/CertPathReviewerMessages_de.properties",
            "org/bouncycastle/pkix/CertPathReviewerMessages.properties",
            "/META-INF/{AL2.0,LGPL2.1}",
            "win32-x86-64/attach_hotspot_windows.dll",
            "win32-x86/attach_hotspot_windows.dll",
            "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            "META-INF/licenses/*",
        ).forEach { resources.excludes.add(it) }
    }

}


val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/signum/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("Indispensable")
                description.set("Kotlin Multiplatform Crypto Core Library, Datatypes and ASN.1 Parser+Encoder")
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
                    developer {
                        id.set("iaik-jheher")
                        name.set("Jakob Heher")
                        email.set("jakob.heher@iaik.tugraz.at")
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
