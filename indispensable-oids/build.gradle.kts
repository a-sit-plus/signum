import at.asitplus.gradle.exportXCFramework
import at.asitplus.gradle.indispensableTargets
import at.asitplus.gradle.signumConventions
import com.squareup.kotlinpoet.AnnotationSpec
import com.squareup.kotlinpoet.ClassName
import com.squareup.kotlinpoet.CodeBlock
import com.squareup.kotlinpoet.FileSpec
import com.squareup.kotlinpoet.FunSpec
import com.squareup.kotlinpoet.KModifier
import com.squareup.kotlinpoet.MemberName
import com.squareup.kotlinpoet.PropertySpec
import java.io.FileInputStream
import java.util.regex.Pattern

buildscript {
    dependencies {
        classpath(libs.kotlinpoet)
    }
}

plugins {
    id("at.asitplus.signum.buildlogic")
}

private val Triple<*, String?, String>.comment: String? get() = this.second
private val Triple<String, *, String>.oid: String? get() = this.first
private val Triple<String, *, String>.originalDescription: String get() = this.third

generateKnownOIDs()

tasks.register<DefaultTask>("regenerateKnownOIDs") {
    doFirst { generateKnownOIDs() }
}

fun generateKnownOIDs() {
    logger.lifecycle("  Regenerating KnownOIDs.kt")
    val collected = mutableMapOf<String, Triple<String, String?, String>>()

    var oid: String? = null
    var comment: String? = null
    var description: String? = null
    var originalDescription: String? = null

    FileInputStream(
        project.layout.projectDirectory.dir("src").file("dumpasn1.cfg").asFile
    ).reader().forEachLine { line ->
        if (!(line.isBlank() || line.startsWith("#"))) {
            if (line.startsWith("OID = ")) {
                val newOID = line.substring("OID = ".length).trim()
                if (oid != null) {
                    val segments = oid!!.split(Pattern.compile("\\s"))
                    if (segments.size > 1 && segments[1].toUInt() > 39u) {
                        logger.warn("w: Skipping OID $oid $description ($comment)")
                    } else {
                        collected[description]?.also {
                            collected["${description}_${oid!!.replace(" ", "_")}"] =
                                Triple(oid!!, comment, originalDescription!!)
                        } ?: run {
                            collected[description!!] = Triple(oid!!, comment, originalDescription!!)
                        }
                    }
                }
                oid = newOID
                description = null
                comment = null
            } else if (line.startsWith("Description = ")) {
                originalDescription = line.substring("Description = ".length).trim()
                description = originalDescription!!
                    .replace("?", "")
                    .replace("(", "")
                    .replace(")", "")
                    .replace("#", "")
                    .replace("\"", "")
                    .replace(' ', '_')
                    .replace('-', '_')
                    .replace(",", "")
                    .ifBlank { oid!!.replace(" ", "_") }
            } else if (line.startsWith("Comment = ")) {
                comment = line.substring("Comment = ".length).trim()
            }
        }
    }

    val legacyPackage = "at.asitplus.signum.indispensable.asn1"
    val upstreamPackage = "at.asitplus.awesn1"
    val legacyKnownOids = ClassName(legacyPackage, "KnownOIDs")
    val oidType = ClassName(legacyPackage, "ObjectIdentifier")

    val knownOidsFile = FileSpec.builder(legacyPackage, "KnownOidConstants").apply {
        collected.toList()
            .distinctBy { (_, oidTriple) -> oidTriple.oid }
            .sortedBy { (name, _) -> name }
            .forEach { (name, oidTriple) ->
                val upstreamAlias = "awesn1_${name.replace('`', '_')}"
                addAliasedImport(MemberName(upstreamPackage, name), upstreamAlias)
                addProperty(
                    PropertySpec.builder(name, oidType)
                        .receiver(legacyKnownOids)
                        .addAnnotation(
                            AnnotationSpec.builder(Deprecated::class)
                                .addMember(
                                    "%S, %L",
                                    "Moved to at.asitplus.awesn1.KnownOIDs.`$name`.",
                                    CodeBlock.of(
                                        "ReplaceWith(%S)",
                                        "at.asitplus.awesn1.KnownOIDs.`$name`"
                                    )
                                )
                                .build()
                        )
                        .getter(
                            FunSpec.getterBuilder()
                                .addCode("return at.asitplus.awesn1.KnownOIDs.run { $upstreamAlias }\n")
                                .build()
                        )
                        .addKdoc(
                            "`${oidTriple.oid!!.replace(' ', '.')}`: ${oidTriple.comment ?: oidTriple.originalDescription}"
                        )
                        .build()
                )
            }
    }.build()

    val generatedRoot = project.layout.projectDirectory.dir("generated").dir("commonMain").dir("kotlin")
    knownOidsFile.writeTo(generatedRoot.asFile)
    generatedRoot.file("at/asitplus/signum/indispensable/asn1/OidMap.kt").asFile.delete()
}

signumConventions {
    android("at.asitplus.signum.indispensable.oids")
    mavenPublish(
        name = "Indispensable OIDs",
        description = "Kotlin Multiplatform ASN.1 Object Identifiers"
    )
}

kotlin {
    indispensableTargets()
    project.gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }

    sourceSets {
        commonMain {
            kotlin.srcDir(
                project.layout.projectDirectory.dir("generated")
                    .dir("commonMain").dir("kotlin")
            )

            dependencies {
                api(project(":indispensable-asn1"))
                api("at.asitplus.awesn1:oids:${libs.versions.awesn1.get()}")
            }
        }
    }
}

exportXCFramework(
    "IndispensableOIDs",
    transitiveExports = false,
    static = false,
)
