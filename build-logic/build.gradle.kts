plugins {
    `kotlin-dsl`
}

group = "at.asitplus.signum.buildlogic"

java {
    val preferredVersions = listOf(21, 17)
    val toolchains = project.extensions.getByType(org.gradle.jvm.toolchain.JavaToolchainService::class.java)

    val availableVersion = preferredVersions.firstOrNull { version ->
        try {
            toolchains.launcherFor {
                languageVersion.set(JavaLanguageVersion.of(version))
            }.get()
            true
        } catch (_: Exception) {
            false
        }
    } ?: 17 // fallback if neither found

    toolchain {
        languageVersion.set(JavaLanguageVersion.of(availableVersion))
    }

    println("Using Java toolchain version: $availableVersion")
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
