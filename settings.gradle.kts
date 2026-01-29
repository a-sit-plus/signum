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

plugins {
    id("com.gradle.develocity") version "4.2.2"
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

develocity {
    buildScan {
        termsOfUseUrl = "https://gradle.com/help/legal-terms-of-use"
        if (System.getenv("CI") != null) termsOfUseAgree = "yes"
        publishing.onlyIf { gradle.startParameter.isBuildScan }
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
gradle.startParameter.taskNames.firstOrNull { it.contains("publish") } ?: include(":internals-test")
rootProject.name = "Signum"
include("cinterop")