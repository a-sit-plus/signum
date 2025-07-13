pluginManagement {
    repositories {
        mavenLocal()
        google()
        mavenCentral()
        gradlePluginPortal()
        maven("https://central.sonatype.com/repository/maven-snapshots/")
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots")
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

dependencyResolutionManagement {
    repositories {
        mavenLocal()
        google()
        mavenCentral()
        mavenLocal()
    }
}

include(":internals")
include(":indispensable-asn1")
include(":indispensable")
include(":indispensable-josef")
include(":indispensable-cosef")
include(":supreme")
rootProject.name = "Signum"
