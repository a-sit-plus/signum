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
    project.gradle.startParameter.taskNames.firstOrNull { it.contains("publish") }?.let {
        watchosDeviceArm64()
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(project(":indispensable-asn1"))
                implementation(libs.kotlinx.io.core)
            }
        }
        jvmMain.dependencies {
            api(kotlin("reflect"))
            api(libs.classgraph)
            implementation(project(":internals"))
            implementation(kotest("assertions-core"))
            implementation(serialization("json"))
            implementation(libs.kotlinx.metadata.jvm)
        }
    }
}

