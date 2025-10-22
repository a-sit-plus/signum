plugins {
    `kotlin-dsl`
}

group = "at.asitplus.signum.buildlogic"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

gradlePlugin {
    plugins {
        create("signumConventions") {
            id = "at.asitplus.signum.buildlogic"
            implementationClass = "at.asitplus.gradle.SignumConventionsPlugin"
            displayName = "Signum Build Logic Conventions"
            description = "Common build logic for Signum (skeleton)"
        }
    }
}

dependencies {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()

    implementation("org.jetbrains.kotlin.multiplatform:org.jetbrains.kotlin.multiplatform.gradle.plugin:$kotlinVer")
    implementation(libs.agp)
    implementation(libs.asp)
}

repositories {
    maven {
        url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
        name = "aspConventions"
    }
    mavenLocal()
    gradlePluginPortal()
    google()
    mavenCentral()
}
