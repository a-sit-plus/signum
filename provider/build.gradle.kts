import at.asitplus.gradle.*
import com.squareup.kotlinpoet.AnnotationSpec
import com.squareup.kotlinpoet.ClassName
import com.squareup.kotlinpoet.CodeBlock
import com.squareup.kotlinpoet.FileSpec
import com.squareup.kotlinpoet.TypeName
import com.squareup.kotlinpoet.TypeSpec
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree.Companion.instrumentedTest
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree.Companion.test
import java.io.FileInputStream
import java.util.regex.Pattern


plugins {
    id("com.android.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    id("signing")
    id("io.github.ttypic.swiftklib") version "0.5.2"
    id("at.asitplus.gradle.conventions")
}

buildscript {
    dependencies {
        classpath(libs.kotlinpoet)
    }
}


val kmp_crypto: String by project


version = "0.0.4-SNAPSHOT"

wireAndroidInstrumentedTests()

kotlin {
    jvm()
    androidTarget {
        publishLibraryVariants("release")
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        instrumentedTestVariant.sourceSetTree.set(test)
    }
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64(),
    ).forEach { iosTarget -> //Hella inefficient, but reliable
        iosTarget.compilations.getByName("main") {
            cinterops {
                create("Krypto")
            }
        }
    }
    sourceSets.commonMain.dependencies {
        implementation(coroutines())
        implementation(napier())
        api(project(":datatypes"))
        api(kotlincrypto.core.digest)
        implementation(kotlincrypto.hash.sha1)
        implementation(kotlincrypto.hash.sha2)
        implementation(kotlincrypto.secureRandom)
    }
    /*
    sourceSets.androidMain.dependencies {
        implementation("androidx.biometric:biometric:1.2.0-alpha05")
    }
    */

}

swiftklib {
    create("Krypto") {
        minIos = 14
        path = file("src/swift")
        packageName("at.asitplus.swift.krypto")
    }
}

android {
    namespace = "at.asitplus.crypto.android"
    compileSdk = 34
    defaultConfig {
        minSdk = 33
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }


    dependencies {
        androidTestImplementation(libs.runner)
        androidTestImplementation(libs.core)
        androidTestImplementation(libs.rules)
        androidTestImplementation(libs.kotest.runner.android)
        testImplementation(libs.kotest.extensions.android)
    }

    packaging {
        resources.excludes.add("/META-INF/{AL2.0,LGPL2.1}")
        resources.excludes.add("win32-x86-64/attach_hotspot_windows.dll")
        resources.excludes.add("win32-x86/attach_hotspot_windows.dll")
        resources.excludes.add("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
        resources.excludes.add("META-INF/licenses/*")
    }

    testOptions {
        managedDevices {
            localDevices {
                create("pixel2api33") {
                    device = "Pixel 2"
                    apiLevel = 33
                    systemImageSource = "aosp-atd"
                }
            }
        }
    }
}

exportIosFramework(
    "KmpCryptoProvider",
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":datatypes"),
    libs.bignum
)

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/kmp-crypto/tree/main/",
    multiModuleDoc = true
)

repositories {
    maven("https://repo1.maven.org/maven2")
}

publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("KMP Crypto Provider")
                description.set("Kotlin Multiplatform Crypto Provider")
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


fun wireAndroidInstrumentedTests() {
    logger.lifecycle("  Wiring up Android Instrumented Tests")

    project.layout.projectDirectory.dir("src").dir("commonTest")
        .dir("kotlin").asFileTree.filter { it.extension == "kt" }.forEach { file ->
            FileInputStream(file).bufferedReader().use { reader ->
                val source = reader.readText()

                val pacakgeName =
                    Pattern.compile("package\\s+.+\\s", Pattern.UNICODE_CHARACTER_CLASS)
                        .matcher(source).run {
                            if (find()) {
                                group().replaceFirst("package", "").trim()
                            } else null
                        }
                val pattern = Pattern.compile(
                    "open\\s+class\\s+.+\\s*FreeSpec",
                    Pattern.UNICODE_CHARACTER_CLASS
                )
                val matcher = pattern.matcher(source)

                while (matcher.find()) {
                    logger.lifecycle("Found Test class in file ${file.name}")
                    val match = matcher.group().replace(":", "")
                    val extractPAttern = Pattern.compile(
                        "open\\s+class\\s+[^\\s-]+",
                        Pattern.UNICODE_CHARACTER_CLASS
                    )
                    val extractMatcher = extractPAttern.matcher(match).also { it.find() }
                    val extracted = extractMatcher.group()

                    val deletePattern =
                        Pattern.compile("open\\s+class\\s+", Pattern.UNICODE_CHARACTER_CLASS)
                    val deleteMatcher = deletePattern.matcher(extracted).also { it.find() }

                    val className = extracted.substring(deleteMatcher.end())

                    FileSpec.builder(pacakgeName ?: "", "Android$className")
                        .addType(
                            TypeSpec.classBuilder("Android$className")
                                .apply {
                                    this.superclass(ClassName(pacakgeName ?: "", className))
                                    annotations += AnnotationSpec.builder(
                                        ClassName(
                                            "org.junit.runner",
                                            "RunWith"
                                        )
                                    )
                                        .addMember(
                                            "%L",
                                            "br.com.colman.kotest.KotestRunnerAndroid::class"
                                        )
                                        .build()
                                }.build()
                        ).build().apply {
                            project.layout.projectDirectory.dir("src")
                                .dir("androidInstrumentedTest").dir("kotlin")
                                .dir("generated").asFile.also { file ->
                                    file.mkdirs()
                                    writeTo(file)
                                }
                        }

                }
            }
        }
}