import at.asitplus.gradle.*

plugins {
    id("at.asitplus.signum.buildlogic")
}

signumConventions {
    android("at.asitplus.signum.extensibility.test", 30)
}

kotlin {
    jvm()

    sourceSets {
        commonTest.dependencies {
            implementation(project(":supreme"))
        }
    }
}
