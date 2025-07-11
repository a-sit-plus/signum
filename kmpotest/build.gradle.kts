import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl


plugins {
    id("com.android.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
version = artifactVersion

fun getTempDir() {
    val tempDir = System.getProperty("java.io.tmpdir")
    val dir = project.layout.projectDirectory.dir("generated")
        .dir("commonMain").dir("kotlin")
    val targetDir= dir.asFile
    targetDir.mkdirs()
    val tempFile = dir.file("temp.kt").asFile
    tempFile.writer().use {
        logger.warn("writing tmpdir tp ${tempFile.absolutePath}")
        it.write("const val KOTEST_REPORT_TEMPDIR = \"$tempDir\"")
    }
}
getTempDir()


kotlin {
    jvm()
    androidTarget { publishLibraryVariants("release") }
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
    //watchosDeviceArm64() //TODO for release: enable this target
    tvosSimulatorArm64()
    tvosX64()
    tvosArm64()
    androidNativeX64()
     androidNativeX86()
     androidNativeArm32()
     androidNativeArm64()

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

        commonMain {
            kotlin.srcDir(
                project.layout.projectDirectory.dir("generated")
                    .dir("commonMain").dir("kotlin")
            )
            dependencies {
                implementation(libs.xmlutil)
                implementation(libs.kotlinx.io.core)
                api(kotest("framework-engine"))
            }
        }


    }
}

android {
    namespace = "at.asitplus.signum.kmpotest"
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

// we don't have native android tests independent of our regular test suite.
// this task expect those and fails, since no tests are present, so we disable it.
project.gradle.taskGraph.whenReady {
    tasks.getByName("testDebugUnitTest") {
        enabled = false
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
                name.set("Indispensable KMPotest")
                description.set("Kotlin Multiplatform Kotest JUnit report generator shim")
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
