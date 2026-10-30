import at.asitplus.gradle.*
import java.net.URI

plugins {
    id("at.asitplus.signum.buildlogic")
}

// Build-time embedded CA bundle (Apple's open-source PKITrustStore, pinned via `appleTrustStoreRef`),
// generated into commonMain so [BundledTrustStore] is available on every target without `supreme`.
val bundledRootsSrcDir = layout.buildDirectory.dir("generated/bundledRoots/kotlin")


signumConventions {
    android("at.asitplus.signum.indispensable.pkix")
    mavenPublish(
        name = "Indispensable PKIX",
        description = "Kotlin Multiplatform Crypto Library - Typed X.509 PKIX extensions and attributes"
    )
}


// ---- BundledTrustStore source generation -------------------------------------------------------
// Downloads Apple's open-source PKITrustStore (apple-oss-distributions/security_certificates) at the
// version pinned by `appleTrustStoreRef`, and hex-encodes every certificates/roots/*.cer (DER) into a
// generated `bundledRoots` list consumed by BundledTrustStore. See that class's KDoc for provenance.
// Registered before the `kotlin {}` block so the source set can consume the task provider directly and
// every downstream task (compile, sources jars, metadata) inherits the dependency automatically.

val appleTrustStoreRef: String by project.extra

val downloadDir = layout.buildDirectory.dir("apple")
val archiveFile = downloadDir.map { it.file("security_certificates-$appleTrustStoreRef.zip") }
val rootsDir = layout.buildDirectory.dir("apple-roots")

val downloadAppleTrustStore = tasks.register("downloadAppleTrustStore") {
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

val generateBundledRootsSource = tasks.register("generateBundledRootsSource") {
    dependsOn(unpackAppleRoots)

    outputs.dir(bundledRootsSrcDir)

    val outputFile = bundledRootsSrcDir.map { it.file("BundledRoots.kt") }

    doLast {
        val outFile = outputFile.get().asFile
        outFile.parentFile.mkdirs()

        val roots = rootsDir.get().asFile
        val cerFiles = roots
            .listFiles { f -> f.isFile && f.extension.equals("cer", ignoreCase = true) }
            ?.sortedBy { it.name }
            ?: emptyList()

        val sb = StringBuilder()
        sb.appendLine("package at.asitplus.signum.indispensable.pki")
        sb.appendLine()
        sb.appendLine("/** Build-time embedded CA roots (hex-encoded DER) backing [BundledTrustStore]. */")
        sb.appendLine("internal val bundledRoots = listOf(")

        cerFiles.forEach { file ->
            val bytes = file.readBytes().toHexString()
            sb.appendLine("\"$bytes\",")

        }
        sb.appendLine(")")

        sb.appendLine()

        outFile.writeText(sb.toString())
        println("Generated ${cerFiles.size} bundled root certs into ${outFile.absolutePath}")
    }
}


kotlin {
    indispensableTargets()

    sourceSets {
        commonMain {
            // Consume the generator's task provider (not the bare directory) so Gradle wires an
            // implicit dependency into every task that reads this source dir — compile tasks as well
            // as the `*SourcesJar` / metadata jars that would otherwise trip Gradle 9's validation.
            kotlin.srcDir(generateBundledRootsSource)
            dependencies {
                api(project(":indispensable"))
                implementation(project(":internals"))
                implementation(libs.bignum) //Intellij bug work-around
                api(libs.cidre)
                api(libs.urikmp)
            }
        }

        jvmTest {
            dependencies {
                implementation(project(":supreme"))
                gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?:implementation(project(":internals-test"))
            }
        }
    }
}

exportXCFramework(
    "IndispensablePkix",
    transitiveExports = false,
    static = false,
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":indispensable"),
    libs.awesn1.crypto,
    libs.awesn1.oids,
    libs.bignum,
    libs.cidre,
    libs.urikmp
)
