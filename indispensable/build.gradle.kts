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


kotlin {
    indispensableTargets()

    sourceSets {
        commonMain.dependencies {
            api(kmmresult())
            api(libs.awesn1.crypto)
            api(libs.awesn1.oids)
            api(libs.awesn1.io)
            api(libs.multibase)
            api(libs.bignum)
            implementation(project(":internals"))
            api(libs.securerandom)
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