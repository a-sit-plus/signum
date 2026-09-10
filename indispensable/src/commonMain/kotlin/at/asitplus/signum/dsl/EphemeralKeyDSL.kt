package at.asitplus.signum.dsl

open class InMemorySignerConfiguration: DSL.Data()
val InMemorySignerConfiguration.jvm get() =
    childOrDefault("JVM", ::JVMEphemeralConfiguration)
class EphemeralSignerConfiguration: InMemorySignerConfiguration() {
    val _algSpecific = subclassOf<AlgorithmSpecific>("ALG_SPECIFIC_CONFIG")
    abstract class AlgorithmSpecific : DSL.Data()
}
