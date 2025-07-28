import at.asitplus.gradle.at.asitplus.gradle.getBuildableTargets
import org.jetbrains.dokka.gradle.DokkaMultiModuleTask
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import java.time.Duration

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val kotestVer = System.getenv("KOTEST_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotest.get()
    val kspVer = System.getenv("KSP_VERSION_ENV")?.ifBlank { null } ?: "$kotlinVer-${libs.versions.ksp.get()}"

    id("at.asitplus.gradle.conventions") version "20250727"
    id("io.kotest") version kotestVer
    kotlin("multiplatform") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.android.library") version libs.versions.agp.get() apply (false)
    id("com.google.devtools.ksp") version kspVer
}
group = "at.asitplus.signum"

//work around nexus publish bug
val artifactVersion: String by extra
version = artifactVersion

nexusPublishing {
    transitionCheckOptions {
        maxRetries.set(200)
        delayBetween.set(Duration.ofSeconds(20))
    }
    connectTimeout.set(Duration.ofMinutes(15))
    clientTimeout.set(Duration.ofMinutes(15))
}
//end work around nexus publish bug

//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(File("${buildDir}/dokka"))
    moduleName.set("Signum")
}

allprojects {
    apply(plugin = "org.jetbrains.dokka")
    group = rootProject.group
}

subprojects {
    afterEvaluate {
        val targets = project.extensions.getByType<KotlinMultiplatformExtension>().targets
        val buildableTargets = getBuildableTargets()
        if (targets.size > buildableTargets.size) {
            logger.warn(
                ">>>> The following targets are not buildable on the current host: ${
                    targets.map { it.name }.toMutableSet().apply { removeAll(buildableTargets.map { it.name }) }
                        .joinToString(", ")
                } <<<<"
            )
            logger.warn("     disabling checkKotlinGradlePluginConfigurationErrors for project $name")
            tasks.findByName("checkKotlinGradlePluginConfigurationErrors")?.enabled = false
        }
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

tasks.register<Copy>("mkDocsPrepare") {
    dependsOn("dokkaHtmlMultiModule")
    dependsOn("copyChangelog")
    dependsOn("copyAppLegend")
    into(rootDir.resolve("docs/docs/dokka"))
    from("${buildDir}/dokka")
}

tasks.register<Exec>("mkDocsBuild") {
    dependsOn(tasks.named("mkDocsPrepare"))
    workingDir("${rootDir}/docs")
    commandLine("mkdocs", "build", "--clean", "--strict")
}

tasks.register<Copy>("mkDocsSite") {
    dependsOn("mkDocsBuild")
    into(rootDir.resolve("docs/site/assets/images/social"))
    from(rootDir.resolve("docs/docs/assets/images/social"))
}
