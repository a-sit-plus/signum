plugins { kotlin("jvm") version "2.4.10" }
kotlin { jvmToolchain(17) }
dependencies {
    testImplementation("at.asitplus.signum:indispensable:3.26.0")
    testImplementation("at.asitplus.signum:indispensable-josef:3.26.0")
    testImplementation("at.asitplus.signum:indispensable-cosef:3.26.0")
    testImplementation("at.asitplus.signum:supreme:0.16.0")
    testImplementation(kotlin("test-junit"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
}
tasks.test { useJUnit(); testLogging { events("passed", "failed", "skipped") } }
