@file:OptIn(ExperimentalKotlinGradlePluginApi::class)

import at.asitplus.gradle.AspVersions
import at.asitplus.gradle.coroutines
import at.asitplus.gradle.napier
import at.asitplus.gradle.signumConventions
import org.jetbrains.kotlin.daemon.common.toHexString
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.konan.target.HostManager
import java.net.URI

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.supreme", 30)
    mavenPublish(
        name = "Signum Supreme",
        description = "Kotlin Multiplatform Crypto Provider"
    )
    supreme = true
}

val appleRootsSrcDir = layout.buildDirectory.dir("generated/appleRoots/kotlin")


kotlin {
    jvm()

    val iosTargets = listOf(iosX64(), iosArm64(), iosSimulatorArm64())
    // Adapted from https://github.com/openwallet-foundation/multipaz
    iosTargets.forEach { target ->
        val platform = when (target.name) {
            "iosX64" -> "iphonesimulator"
            "iosArm64" -> "iphoneos"
            "iosSimulatorArm64" -> "iphonesimulator"
            else -> error("Unsupported target ${target.name}")
        }
        if (HostManager.hostIsMac) {
            target.compilations.getByName("main") {
                val cinterop by cinterops.creating {
                    definitionFile.set(file("$rootDir/cinterop/AESwift-$platform.def"))
                    includeDirs.headerFilterOnly("$rootDir/cinterop/build/Release-$platform/include")

                    val interopTask = tasks[interopProcessingTaskName]
                    interopTask.dependsOn(":cinterop:buildIphoneos")
                    interopTask.dependsOn(":cinterop:buildIphonesimulator")
                }

                target.binaries.all {
                    linkerOpts(
                        "-L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/${platform}/",
                        "-L$rootDir/cinterop/build/Release-${platform}",
                        "-lAESwift"
                    )
                }
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            api(project(":indispensable"))
            implementation(project(":internals"))
            implementation(coroutines())
            implementation(napier()) //TODO: modulator!
            implementation(libs.securerandom) //fix composite build
        }

        androidMain.dependencies {
            implementation("androidx.biometric:biometric:1.2.0-alpha05")
        }

        commonTest.dependencies {
            implementation("at.asitplus:kmmresult-test:${AspVersions.kmmresult}")
        }
        iosMain{
            kotlin.srcDir(appleRootsSrcDir)
        }

        jvmTest.dependencies {
            implementation("com.lambdaworks:scrypt:1.4.0")
        }
    }
}


/*
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
*/

val appleTrustStoreRef: String by project.extra

val downloadDir = layout.buildDirectory.dir("apple")
val archiveFile = downloadDir.map { it.file("security_certificates-$appleTrustStoreRef.zip") }
val rootsDir = layout.buildDirectory.dir("apple-roots")

val downloadAppleTrustStore = tasks.register("downloadAppleTrustStore") {
    // tell Gradle what this task produces
    outputs.file(archiveFile)

    doLast {
        val url = URI(
            "https://github.com/apple-oss-distributions/security_certificates/archive/refs/tags/$appleTrustStoreRef.zip"
        ).toURL()

        val outFile = archiveFile.get().asFile
        outFile.parentFile.mkdirs()

        if (!outFile.exists()) {
            println("Downloading Apple trust store from $url")
            url.openStream().use { input ->
                outFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
        } else {
            println("Using cached ${outFile.absolutePath}")
        }
    }
}

val unpackAppleRoots = tasks.register<Copy>("unpackAppleRoots") {
    dependsOn(downloadAppleTrustStore)

    from({ zipTree(archiveFile.get().asFile) }) {
        include("**/certificates/roots/*.cer")
        // flatten into a single directory
        eachFile { path = name }
        includeEmptyDirs = false
    }

    into(rootsDir)
}

tasks.register("fetchAppleRoots") {
    description = "Downloads and unpacks Apple PKITrustStore root certificates"
    group = "verification"
    dependsOn(unpackAppleRoots)
}

val generateAppleRootsSource = tasks.register("generateAppleRootsSource") {
    dependsOn(unpackAppleRoots)

    val outputFile = appleRootsSrcDir.map { it.file("AppleRoots.kt") }
    outputs.file(outputFile)

    doLast {
        val outFile = outputFile.get().asFile
        outFile.parentFile.mkdirs()

        val roots = rootsDir.get().asFile
        val cerFiles = roots
            .listFiles { f -> f.isFile && f.extension.equals("cer", ignoreCase = true) }
            ?.sortedBy { it.name }
            ?: emptyList()

        val sb = StringBuilder()
        sb.appendLine("package at.asitplus.signum.supreme.validate")
        sb.appendLine()
        sb.appendLine("internal val appleRoots = listOf(")

        cerFiles.forEach { file ->
            val bytes = file.readBytes().toHexString()
            sb.appendLine("\"$bytes\",")

        }
        sb.appendLine(")")

        sb.appendLine()

        outFile.writeText(sb.toString())
        println("Generated ${cerFiles.size} Apple root certs into ${outFile.absolutePath}")
    }
}

tasks.filter { it.name.startsWith("compileKotlinIos")}.forEach {
    it.dependsOn(generateAppleRootsSource)
}
