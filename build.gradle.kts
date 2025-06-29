import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("at.asitplus.gradle.conventions") version "20250628"
    id("io.kotest.multiplatform") version (System.getenv("KOTEST_VERSION_ENV")?.let { it.ifBlank { null } }
        ?: libs.versions.kotest.get())
    kotlin("multiplatform") version (System.getenv("KOTLIN_VERSION_ENV")?.let { it.ifBlank { null } }
        ?: libs.versions.kotlin.get()) apply false
    kotlin("plugin.serialization") version (System.getenv("KOTLIN_VERSION_ENV")?.let { it.ifBlank { null } }
        ?: libs.versions.kotlin.get()) apply false
    id("com.android.library") version "8.6.1" apply (false)
}
group = "at.asitplus.signum"

//Kotest workaround
rootProject.also {
    listOf(
        it.file("./indispensable/src/iosTest/kotlin/Test.ktjsTest/"),
        it.file("./supreme/src/iosTest/kotlin/Test.ktjsTest/"),
        it.file("./indispensable/src/commonTest/kotlin/Asn1AddonsTest.ktjsTest/"),
        it.file("./indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/Asn1BitStringTest.ktjsTest/"),
    ).forEach {
        logger.lifecycle(">>> DELETING $it")
        it.deleteRecursively()
    }
}
//next kotest workaround
subprojects {
    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
        // Apply opt-in only for test sources
        if (name.contains("test", ignoreCase = true)) {
            compilerOptions {
                optIn.add("kotlin.ExperimentalStdlibApi")
            }
        }
    }
}

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
