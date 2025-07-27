pluginManagement {
    repositories {
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
        google()
        mavenCentral()
        mavenLocal()
    }
}

gradle.allprojects {
    // run after each project is evaluated so that the plugin has
    // already added whatever it wanted to add
    afterEvaluate {
        repositories.removeIf { repo ->
            repo is MavenArtifactRepository &&
                    repo.url.toString().contains("https://s01.oss.sonatype.org/content/repositories")
        }
    }
}


include(":internals")
include(":indispensable-asn1")
include(":indispensable-oids")
include(":indispensable")
include(":indispensable-josef")
include(":indispensable-cosef")
include(":supreme")
rootProject.name = "Signum"
