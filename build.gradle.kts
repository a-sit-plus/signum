import org.jetbrains.dokka.gradle.DokkaMultiModuleTask
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import java.time.Duration

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()

    id("at.asitplus.gradle.conventions") version "20251003"
    kotlin("multiplatform") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.android.kotlin.multiplatform.library") version libs.versions.agp.get() apply (false)
    id("de.infix.testBalloon") version libs.versions.testballoon.get() apply false
}
group = "at.asitplus.signum"
subprojects {
    repositories {
        mavenLocal()
    }
}
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

//shush!
subprojects {
    var silentium: Boolean? = null
    project.extensions.getByType<KotlinMultiplatformExtension>().targets.whenObjectAdded {
        val buildableTargets = getBuildableTargets()
        if (this !in buildableTargets) {
            logger.warn(">>>> Target $this is not buildable on the current host! <<<<")
            project.extensions.getByType<KotlinMultiplatformExtension>().targets.remove(this)
            if (silentium == null) silentium = false
        }
        if (silentium == false) {
            logger.warn("     disabling checkKotlinGradlePluginConfigurationErrors for project $name. YOLO!!!")
            tasks.findByName("checkKotlinGradlePluginConfigurationErrors")?.enabled = false
            silentium = true
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


fun Project.getBuildableTargets() =
    project.extensions.getByType<KotlinMultiplatformExtension>().targets.filter { target ->
        when {
            // Non-native targets are always buildable
            target.platformType != org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType.native -> true
            else -> runCatching {
                val konanTarget = (target as? KotlinNativeTarget)
                konanTarget?.publishable == true
            }.getOrElse { false }
        }
    }

