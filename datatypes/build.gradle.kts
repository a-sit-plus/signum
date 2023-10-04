import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.datetime
import at.asitplus.gradle.serialization

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("at.asitplus.gradle.conventions")
}

group = "at.asitplus.crypto"
version = "1.0-SNAPSHOT"

val encoding = "1.2.3"
val okio = "3.5.0"

kotlin {


    sourceSets {
        val commonMain by getting {
            dependencies {
                api(serialization("json"))
                api(datetime())
                implementation("io.matthewnelson.kotlin-components:encoding-base16:${encoding}")
                implementation("io.matthewnelson.kotlin-components:encoding-base64:${encoding}")
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
