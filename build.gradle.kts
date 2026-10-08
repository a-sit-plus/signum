import at.asitplus.gradle.dokka
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import java.time.Duration

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val testballoonVer = System.getenv("TESTBALLOON_VERSION_OVERRIDE")?.ifBlank { null } ?: libs.versions.testballoon.get()

    alias(libs.plugins.asp)
    kotlin("multiplatform") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.android.kotlin.multiplatform.library") version libs.versions.agp.get() apply (false)
    id("de.infix.testBalloon") version testballoonVer apply false
}
group = "at.asitplus.signum"
subprojects {
    repositories {
        mavenLocal()
    }
}
//work around nexus publish bug
val indispensableVersion: String by extra
version = indispensableVersion

nexusPublishing {
    transitionCheckOptions {
        maxRetries.set(400)
        delayBetween.set(Duration.ofSeconds(20))
    }
    connectTimeout.set(Duration.ofMinutes(15))
    clientTimeout.set(Duration.ofMinutes(40))
}
//end work around nexus publish bug


val dokkaDir = rootProject.layout.buildDirectory.dir("docs")
dokka {
    dokkaPublications.html{
        outputDirectory.set(dokkaDir)
    }
}

val documentedModules = listOf(
    "indispensable", "indispensable-josef", "indispensable-cosef",
    "indispensable-pkix", "supreme", "pkix-supreme",
)
documentedModules.forEach { dependencies.add("dokka", project(":$it")) }

allprojects {
    apply(plugin = "org.jetbrains.dokka")
    group = rootProject.group
    dokka {
        dokkaPublications.configureEach { failOnWarning.set(true) }
    }
}

tasks.register<Copy>("copyChangelog") {
    into(rootDir.resolve("docs/docs"))
    from("CHANGELOG.md")
}
tasks.register<Copy>("copyAppLegend") {
    into(rootDir.resolve("docs/docs/assets"))
    from("demoapp/legend.png")
    from("demoapp/app.png")
}

tasks.named("dokkaGeneratePublicationHtml") {
    doFirst { delete(dokkaDir) }
}

tasks.register<Sync>("mkDocsPrepare") {
    dependsOn("dokkaGenerate")
    dependsOn("copyChangelog")
    dependsOn("copyAppLegend")
    into(rootDir.resolve("docs/docs/dokka"))
    from(dokkaDir)
}

tasks.register<GradleBuild>("legacyDocsTest") {
    group = "verification"
    description = "Runs historical documentation examples against published Signum 3.x."
    dir = rootDir.resolve("docs/legacy-examples")
    tasks = listOf("test")
}

tasks.register<Exec>("checkDocsSnippets") {
    group = "verification"
    description = "Checks that documentation Kotlin fences embed named test-source snippets."
    commandLine("python3", rootDir.resolve("docs/check_snippets.py"), "--self-test")
}

tasks.register("docsTest") {
    group = "verification"
    description = "Runs the JVM tests backing the current and historical documentation examples."
    dependsOn(documentedModules.map { ":$it:jvmTest" })
    dependsOn(":extensibility-test:jvmTest", "legacyDocsTest", "checkDocsSnippets")
}

tasks.register<Exec>("mkDocsBuild") {
    dependsOn(tasks.named("mkDocsPrepare"))
    dependsOn("docsTest")
    workingDir("${rootDir}/docs")
    val mkdocs = providers.environmentVariable("VIRTUAL_ENV")
        .map { "$it/bin/mkdocs" }.getOrElse("mkdocs")
    commandLine(mkdocs, "build", "--clean", "--strict")
}

tasks.register<Copy>("mkDocsSite") {
    dependsOn("mkDocsBuild")
    into(rootDir.resolve("docs/site/assets/images/social"))
    from(rootDir.resolve("docs/docs/assets/images/social"))
}
