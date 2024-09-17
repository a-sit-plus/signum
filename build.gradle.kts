import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("at.asitplus.gradle.conventions") version "2.0.20+20240917"
    id("com.android.library") version "8.2.2" apply (false)
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
    includes.from("README.md")
    moduleName.set("Signum")
    doLast {
        files(
            "core-dark.png",
            "core-light.png",
            "cosef-dark.png",
            "cosef-light.png",
            "supreme-dark.png",
            "supreme-light.png",
            "josef-dark.png",
            "josef-light.png",
            "signum-light-large.png",
            "signum-dark-large.png",
        ).files.forEach { it.copyTo(File("build/dokka/${it.name}"), overwrite = true) }
    }
}

allprojects {
    apply(plugin = "org.jetbrains.dokka")
    group = rootProject.group

    repositories {
        mavenLocal()
    }
}
