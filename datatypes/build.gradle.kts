import at.asitplus.gradle.*
import com.squareup.kotlinpoet.ClassName
import com.squareup.kotlinpoet.FileSpec
import com.squareup.kotlinpoet.PropertySpec
import com.squareup.kotlinpoet.TypeSpec
import java.io.FileInputStream


buildscript {
    dependencies {
        classpath(libs.kotlinpoet)
    }
}

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
version = artifactVersion


private val Pair<*, String?>.comment: String? get() = this.second
private val Pair<String, *>.oid: String? get() = this.first

tasks.register<DefaultTask>("generateOid") {
    val collected = mutableMapOf<String, Pair<String, String?>>()
    doFirst {


        var oid: String? = null
        var comment: String? = null
        var description: String? = null

        FileInputStream(
            project.layout.projectDirectory.dir("src").dir("commonMain").dir("resources").file("dumpasn1.cfg").asFile
        ).reader().forEachLine { line ->
            if (!(line.isBlank() || line.startsWith("#"))) {
                //we know a new OID
                if (line.startsWith("OID = ")) {
                    val newOID = line.substring("OID = ".length).trim()
                    // we know the previously declared OID was fully read
                    if (oid != null) {
                        //if we collected the name of this OID already, we need to assign a new name
                        collected[description]?.also { existing ->
                            collected["${description}_$oid"] = Pair(oid!!, comment)
                        } ?: run {
                            //if it is still new, we can just add it
                            collected[description!!] = Pair(oid!!, comment)
                        }
                    }
                    oid = newOID
                    description = null
                    comment = null
                } else if (line.startsWith("Description = ")) {
                    description = line.substring("Description = ".length).trim().replace("?", "").replace("(", "")
                        .replace(")", "").replace("#", "").replace(",", "").let {
                            it.ifBlank { oid }
                        }
                } else if (line.startsWith("Comment = ")) {
                    comment = line.substring("Comment = ".length).trim()
                }
            }
        }

        collected.forEach { name, oidTriple ->
            println("$name =  ${oidTriple.oid} (${oidTriple.comment})")
        }
    }

    doLast {
        val knownOIDs = ClassName("at.asitplus.crypto.datatypes.asn1", "Known_OIDs")
        val file = FileSpec.builder("at.asitplus.crypto.datatypes.asn1", "Known_OIDs")
            .addType(
                TypeSpec.objectBuilder("Known_OIDs").apply {
                    collected.toList().distinctBy { (_, oidTriple) -> oidTriple.oid }.sortedBy { (name, _) -> name }
                        .forEach { (name, oidTriple) ->
                            addProperty(
                                PropertySpec.builder(
                                    name,
                                    ClassName(packageName = "at.asitplus.crypto.datatypes.asn1", "ObjectIdentifier")
                                )
                                    .initializer("\nObjectIdentifier(\n\"${oidTriple.oid}\"\n)")
                                    .addKdoc("`${oidTriple.oid}`: ${oidTriple.comment}")
                                    .build()
                            )
                        }

                }.build()
            ).build()

        file.writeTo(
            project.layout.projectDirectory.dir("src").dir("commonMain").dir("kotlin").file("KnownOids.kt").asFile
        )
    }
}

tasks.getByName("metadataMainClasses").dependsOn(tasks.getByName("generateOid"))


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

            //workaround [KT-66563](https://youtrack.jetbrains.com/issue/KT-66563/Stop-including-resources-to-metadata-klib)
            //triggering [KT-65315](https://youtrack.jetbrains.com/issue/KT-65315/KMP-Composite-compileIosMainKotlinMetadata-fails-with-Could-not-find-included-iOS-dependency)
            //I'm still inclined to keep it here, should we ever want to crank it up with Kotlinpoet to parse the actual source and not McGyuver-it. That is: once the bugfixes land in production Kotlin
            resources.exclude {
                it.name == "dumpasn1.cfg"
            }

            dependencies {
                api(kmmresult())
                api(serialization("json"))
                api(datetime())
                implementation(libs.base16)
                implementation(libs.base64)
                implementation(libs.bignum)
            }
        }

        commonTest {
            dependencies {
                implementation(kotest("property"))
                implementation(kotlin("reflect"))
            }
        }

        jvmMain {
            dependencies {
                api(bouncycastle("bcpkix"))
            }
        }

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
