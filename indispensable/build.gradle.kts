import at.asitplus.gradle.*

plugins {
    id("at.asitplus.signum.buildlogic")
}


signumConventions {
    android("at.asitplus.signum.indispensable")
    mavenPublish(
        name = "Indispensable",
        description = "Kotlin Multiplatform Crypto Core Library, Datatypes and ASN.1 Parser+Encoder"
    )
}


private val Pair<*, String?>.comment: String? get() = this.second
private val Pair<String, *>.oid: String? get() = this.first

kotlin {
    indispensableTargets()

    sourceSets {
        commonMain.dependencies {
            api(project(":indispensable-asn1"))
            api(project(":indispensable-oids"))
            api(libs.multibase)
            api(libs.bignum)
            implementation(project(":internals"))
            api(libs.kotlinx.coroutines.core)
            api(libs.securerandom)
            api(libs.cidre)
            api(libs.urikmp)
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
    project(":indispensable-asn1"),
    project(":indispensable-oids"),
    libs.bignum
)