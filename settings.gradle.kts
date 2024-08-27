pluginManagement {
    includeBuild("swift-klib-plugin")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

include(":indispensable")
include(":indispensable-josef")
include(":indispensable-cosef")
include(":supreme")
rootProject.name = "Signum"
