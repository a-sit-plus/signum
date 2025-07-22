plugins {
    alias(libs.plugins.multiplatform).apply(false)
    alias(libs.plugins.compose).apply(false)
    alias(libs.plugins.android.application).apply(false)
    alias(libs.plugins.buildConfig).apply(false)
}

allprojects {
    repositories {
        mavenLocal()
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots")
        mavenCentral()
        google()
    }
}