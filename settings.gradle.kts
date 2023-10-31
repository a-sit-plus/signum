pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
    includeBuild("gradle-conventions-plugin")
}
include(":datatypes")
include(":datatypes-jws")
include(":datatypes-cose")
rootProject.name = "kmp-crypto"