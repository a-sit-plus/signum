rootProject.name = "CryptoTest-App"
include(":composeApp")

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()

        //required for indispensable modules
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots")
        //required for indispensable modules
        maven {
            url =
                uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

includeBuild("..") {
    dependencySubstitution {
        substitute(module("at.asitplus.signum:indispensable")).using(project(":indispensable"))
        substitute(module("at.asitplus.signum:indispensable-josef")).using(project(":indispensable-josef"))
        substitute(module("at.asitplus.signum:indispensable-cosef")).using(project(":indispensable-cosef"))
        substitute(module("at.asitplus.signum:supreme")).using(project(":supreme"))
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        mavenLocal()
    }
}
