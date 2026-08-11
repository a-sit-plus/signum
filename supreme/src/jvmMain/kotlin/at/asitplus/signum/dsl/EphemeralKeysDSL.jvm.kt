package at.asitplus.signum.dsl

actual class EphemeralSigningKeyConfiguration internal actual constructor(): EphemeralSigningKeyConfigurationBase() {
    var provider: String? = null
}

interface JvmEphemeralSignerCompatibleConfiguration {
    var provider: String?
}

actual class EphemeralSignerConfiguration internal actual constructor(): EphemeralSignerConfigurationBase(), JvmEphemeralSignerCompatibleConfiguration {
    override var provider: String? = null
}