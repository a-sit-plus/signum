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
    versionCatalogs {
        create("kotlincrypto") {
            // https://github.com/KotlinCrypto/version-catalog/blob/master/gradle/kotlincrypto.versions.toml
            from("org.kotlincrypto:version-catalog:0.5.2")
        }
    }
}

include(":indispensable")
include(":indispensable-josef")
include(":indispensable-cosef")
include(":supreme")
rootProject.name = "Signum"
