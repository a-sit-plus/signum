pluginManagement {
    repositories {
        mavenLocal()
        google()
        mavenCentral()
        gradlePluginPortal()
        maven("https://central.sonatype.com/repository/maven-snapshots/")
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

// Include the local build logic as a composite build
includeBuild("build-logic")

include(":internals")
include(":indispensable-asn1")
include(":indispensable-oids")
include(":indispensable")
include(":indispensable-josef")
include(":indispensable-cosef")
include(":supreme")
rootProject.name = "Signum"
