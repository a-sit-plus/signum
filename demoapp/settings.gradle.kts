rootProject.name = "CryptoTest-App"
include(":composeApp")

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()

        //required for indispensable modules composite build
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots")
        //required for indispensable modules composite build
        maven {
            url =
                uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

includeBuild("..")

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
