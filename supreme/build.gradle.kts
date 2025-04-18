import at.asitplus.gradle.*
import com.squareup.kotlinpoet.AnnotationSpec
import com.squareup.kotlinpoet.ClassName
import com.squareup.kotlinpoet.FileSpec
import com.squareup.kotlinpoet.TypeSpec
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree.Companion.test
import java.io.FileInputStream
import java.util.regex.Pattern


plugins {
    id("com.android.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    id("signing")
    id("at.asitplus.gradle.conventions")
    id("io.github.ttypic.swiftklib") version "0.6.4"
}

buildscript {
    dependencies {
        classpath(libs.kotlinpoet)
    }
}

val supremeVersion: String by extra
version = supremeVersion

wireAndroidInstrumentedTests()

kotlin {
    compilerOptions.freeCompilerArgs.add("-Xexpect-actual-classes")
    applyDefaultHierarchyTemplate()
    jvm()
    androidTarget {
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        instrumentedTestVariant.sourceSetTree.set(test)
        publishLibraryVariants("release")
    }
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.compilations {
            val main by getting {
                cinterops.create("AESwift")
            }
        }
    }

    sourceSets.commonMain.dependencies {
        api(project(":indispensable"))
        implementation(project(":internals"))
        implementation(coroutines())
        implementation(napier())
        implementation(libs.securerandom) //fix composite build
    }

    sourceSets.androidMain.dependencies {
        implementation("androidx.biometric:biometric:1.2.0-alpha05")
    }
}

swiftklib {
    create("AESwift") {
        path = file("src/iosMain/swift")
        //Can't hide this in the iOS sources to consumers and using a discrete module is overkill -> so add "internal" to the package
        packageName("at.asitplus.signum.supreme.symmetric.internal.ios")
    }
}

android {
    namespace = "at.asitplus.signum.supreme"
    defaultConfig {
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

    testOptions {
        targetSdk = androidMinSdk
        managedDevices {
            localDevices {
                create("pixel2api33") {
                    device = "Pixel 2"
                    apiLevel = androidMinSdk!!
                    systemImageSource = "aosp-atd"
                }
            }
        }
    }
}

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/signum/tree/main/",
    multiModuleDoc = true
)

repositories {
    maven("https://repo1.maven.org/maven2")
}

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("Signum Supreme")
                description.set("Kotlin Multiplatform Crypto Provider")
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


fun wireAndroidInstrumentedTests() {
    logger.lifecycle("  Wiring up Android Instrumented Tests")
    val targetDir = project.layout.projectDirectory.dir("src")
        .dir("androidInstrumentedTest").dir("kotlin")
        .dir("generated").asFile.apply { deleteRecursively() }

    val packagePattern = Pattern.compile("package\\s+(\\S+)", Pattern.UNICODE_CHARACTER_CLASS)
    val searchPattern =
        Pattern.compile("open\\s+class\\s+(\\S+)\\s*:\\s*FreeSpec", Pattern.UNICODE_CHARACTER_CLASS)
    project.layout.projectDirectory.dir("src").dir("commonTest")
        .dir("kotlin").asFileTree.filter { it.extension == "kt" }.forEach { file ->
            FileInputStream(file).bufferedReader().use { reader ->
                val source = reader.readText()

                val packageName = packagePattern.matcher(source).run {
                    if (find()) group(1) else null
                }

                val matcher = searchPattern.matcher(source)

                while (matcher.find()) {
                    val className = matcher.group(1)
                    logger.lifecycle("Found Test class $className in file ${file.name}")

                    FileSpec.builder(packageName ?: "", "Android$className")
                        .addType(
                            TypeSpec.classBuilder("Android$className")
                                .apply {
                                    this.superclass(ClassName(packageName ?: "", className))
                                    annotations += AnnotationSpec.builder(
                                        ClassName(
                                            "org.junit.runner",
                                            "RunWith"
                                        )
                                    ).addMember(
                                        "%L",
                                        "br.com.colman.kotest.KotestRunnerAndroid::class"
                                    )
                                        .build()
                                }.build()
                        ).build().apply {
                            targetDir.also { file ->
                                file.mkdirs()
                                writeTo(file)
                            }
                        }
                }
            }
        }
}

exportXCFramework(
    "SignumSupreme",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    project(":indispensable-asn1"),
    libs.bignum
)

project.gradle.taskGraph.whenReady {
    tasks.getByName("testDebugUnitTest") {
        enabled = false
    }
}

