import DatatypeVersions.encoding
import DatatypeVersions.kmmresult
import DatatypeVersions.okio
import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.napier

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("at.asitplus.gradle.conventions")
}

version = "1.0-SNAPSHOT"

kotlin {
    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":datatypes"))
                api("at.asitplus:kmmresult:${kmmresult}")
                implementation("com.squareup.okio:okio:${okio}")
                implementation(napier())
                implementation("io.matthewnelson.kotlin-components:encoding-base16:${encoding}")
                implementation("io.matthewnelson.kotlin-components:encoding-base64:${encoding}")
            }
        }

        val jvmMain by getting {
            dependencies {
                api(bouncycastle("bcpkix"))
            }
        }

        val commonTest by getting
        val jvmTest by getting
    }
}
