@file:OptIn(ExperimentalKotlinGradlePluginApi::class)

import at.asitplus.gradle.AspVersions
import at.asitplus.gradle.coroutines
import at.asitplus.gradle.napier
import at.asitplus.gradle.signumConventions
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi

plugins {
    id("at.asitplus.signum.buildlogic")
    id("io.github.ttypic.swiftklib") version "0.6.4"
}

signumConventions {
    android("at.asitplus.signum.supreme", 30)
    mavenPublish(
        name = "Signum Supreme",
        description = "Kotlin Multiplatform Crypto Provider"
    )
    supreme = true
}


kotlin {
    jvm()

    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.compilations {
            val main by getting { cinterops.create("AESwift") }
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

        jvmTest.dependencies {
            implementation("com.lambdaworks:scrypt:1.4.0")
        }
    }
}


swiftklib {
    create("AESwift") {
        path = file("src/iosMain/swift")
        //Can't hide this in the iOS sources to consumers and using a discrete module is overkill -> so add "internal" to the package
        packageName("at.asitplus.signum.supreme.symmetric.internal.ios")
        minIos = 15
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

