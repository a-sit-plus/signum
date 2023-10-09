import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.datetime
import at.asitplus.gradle.serialization

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
                api(serialization("json"))
                api(datetime())
                implementation("io.matthewnelson.kotlin-components:encoding-base16:${DatatypeVersions.encoding}")
                implementation("io.matthewnelson.kotlin-components:encoding-base64:${DatatypeVersions.encoding}")
            }
            val commonTest by getting {
                dependencies {
                    implementation(at.asitplus.gradle.kotest("property"))
                }
            }
        }

        val jvmMain by getting{
            dependencies {
                api(bouncycastle("bcpkix"))
            }
        }

        val commonTest by getting
        val jvmTest by getting
    }
}
