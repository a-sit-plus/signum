import at.asitplus.gradle.*
import org.gradle.kotlin.dsl.sourceSets

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.indispensable.internals.test")
}



kotlin {
    indispensableTargets()
    watchosDeviceArm64()

    sourceSets {
        commonMain {
            dependencies {
                implementation("at.asitplus.gradle:testballoon-shim:${libs.versions.asp.get()}")
                implementation(libs.kotlinx.io.core)
            }
        }
        jvmMain.dependencies {
            api(kotlin("reflect"))
            api(libs.classgraph)
            implementation(project(":internals"))
            implementation(kotest("assertions-core"))
        }
    }
}

