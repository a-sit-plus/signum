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
includeBuild("buildlogic")
val multibase = file("../multibase")
if (multibase.resolve("build.gradle.kts").isFile) {
    val localVersion = java.util.Properties().apply {
        multibase.resolve("gradle.properties").inputStream().use(::load)
    }.getProperty("artifactVersion")
    val catalogVersion = file("gradle/libs.versions.toml").useLines { lines ->
        lines.firstNotNullOf { Regex("""^multibase\s*=\s*"(.+)"""").find(it)?.groupValues?.get(1) }
    }
    if (org.gradle.util.internal.VersionNumber.parse(localVersion) >= org.gradle.util.internal.VersionNumber.parse(catalogVersion)) {
        logger.lifecycle("Including multibase $localVersion as composite build")
        includeBuild(multibase)
    }
}

include(":internals")
include(":indispensable")
include(":indispensable-josef")
include(":indispensable-cosef")
include(":indispensable-pkix")
include(":supreme")
include(":pkix-supreme")
if (gradle.startParameter.taskNames.none { it.contains("publish") }) {
    include(":internals-test")
    include(":extensibility-test")
}
rootProject.name = "Signum"
include("cinterop")
