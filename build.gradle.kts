import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val kotestVer = System.getenv("KOTEST_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotest.get()
    val kspVer= "$kotlinVer-${libs.versions.ksp.get()}"

    id("at.asitplus.gradle.conventions") version "20250713"
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

    repositories {
        mavenLocal()
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
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
