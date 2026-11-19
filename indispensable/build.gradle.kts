import at.asitplus.gradle.*
import java.nio.file.Files
import java.nio.file.StandardCopyOption

plugins {
    id("at.asitplus.signum.buildlogic")
}

abstract class CaseFoldingSources : ValueSource<File, CaseFoldingSources.Parameters> {
    interface Parameters : ValueSourceParameters {
        val dataFile: RegularFileProperty
        val sourceDirectory: DirectoryProperty
    }

    override fun obtain(): File {
        val directory = parameters.sourceDirectory.get().asFile
        val output = directory.resolve("at/asitplus/signum/indispensable/pki/CaseFoldingMap.kt")
        val source = buildString {
            appendLine("// Generated from Unicode 17.0.0 CaseFolding.txt. See CaseFolding.LICENSE.txt.")
            appendLine("package at.asitplus.signum.indispensable.pki")
            appendLine()
            appendLine("internal object CaseFoldingMap {")
            appendLine("    private val mappings = mapOf(")
            for (line in parameters.dataFile.get().asFile.readLines()) {
                val fields = line.substringBefore('#').split(';').map(String::trim)
                val status = fields.getOrNull(1)
                if (status != "C" && status != "F") continue
                val replacement = fields[2].split(' ').joinToString("") { hex ->
                    Character.toChars(hex.toInt(16)).joinToString("") { char ->
                        "\\u" + char.code.toString(16).padStart(4, '0')
                    }
                }
                appendLine("        0x${fields[0]} to \"$replacement\",")
            }
            appendLine("    )")
            appendLine()
            appendLine("    operator fun get(codePoint: Int): String? = mappings[codePoint]")
            appendLine("}")
        }
        output.parentFile.mkdirs()
        val temporaryFile = Files.createTempFile(output.parentFile.toPath(), output.name, ".tmp")
        try {
            Files.writeString(temporaryFile, source)
            Files.move(
                temporaryFile,
                output.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
        } finally {
            Files.deleteIfExists(temporaryFile)
        }
        return directory
    }
}

// Evaluate during configuration and when Gradle checks a cached configuration.
val caseFoldingSources = providers.of(CaseFoldingSources::class) {
    parameters.dataFile.set(layout.projectDirectory.file("src/commonMain/resources/CaseFolding.txt"))
    parameters.sourceDirectory.set(layout.projectDirectory.dir("gen/commonMain"))
}.get()


signumConventions {
    android("at.asitplus.signum.indispensable")
    mavenPublish(
        name = "Indispensable",
        description = "Kotlin Multiplatform Crypto Core Library, Datatypes and ASN.1 Parser+Encoder"
    )
}


kotlin {
    indispensableTargets()

    sourceSets {
        commonMain { kotlin.srcDir(caseFoldingSources) }

        commonMain.dependencies {
            api(kmmresult())
            api(serialization("json"))
            api(libs.awesn1.crypto)
            api(libs.awesn1.oids)
            api(libs.awesn1.io)
            api(libs.multibase)
            api(libs.bignum)
            implementation(project(":internals"))
            api(libs.securerandom)
            api(libs.cidre)
            api(libs.urikmp)
        }

        commonTest.dependencies {
            implementation(coroutines())
        }

        jvmTest.dependencies {
            gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?:implementation(project(":internals-test"))
        }

        androidJvmMain {
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
    libs.awesn1.crypto,
    libs.awesn1.oids,
    libs.bignum
)
