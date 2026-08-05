pluginManagement {
    repositories {
        providers.gradleProperty("kotlin_repo_url").orNull?.let {
            maven { url = uri(it); name = "kotlinDev" }
        }
        gradlePluginPortal()
    }
}

rootProject.name = "build-logic"

dependencyResolutionManagement {
    repositories {
        providers.gradleProperty("kotlin_repo_url").orNull?.let {
            maven { url = uri(it); name = "kotlinDev" }
        }
        mavenCentral()
        google()
    }
    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}
