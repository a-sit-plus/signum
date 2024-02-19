import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("at.asitplus.gradle.conventions") version "1.9.10+20240219"
}
group = "at.asitplus.crypto"


//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(File("${layout.buildDirectory}/dokka"))
    includes.from("README.md")
    moduleName.set("KMP Crypto")
}

allprojects {
    apply(plugin = "org.jetbrains.dokka")
    group = rootProject.group
}