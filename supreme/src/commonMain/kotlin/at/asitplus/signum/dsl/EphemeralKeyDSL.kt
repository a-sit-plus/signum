package at.asitplus.signum.dsl

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.sign.RSAAlgorithm

open class EphemeralSigningKeyConfigurationBase internal constructor(): SigningKeyConfiguration() {
    class ECConfiguration internal constructor(): SigningKeyConfiguration.ECConfiguration() {
        init { digests = (Digest.entries.asSequence() + sequenceOf<Digest?>(null)).toSet() }
    }
    class RSAConfiguration internal constructor(): SigningKeyConfiguration.RSAConfiguration() {
        init { digests = Digest.entries.toSet(); paddings = RSAAlgorithm.Padding.entries.toSet()}
    }
}

val EphemeralSigningKeyConfigurationBase.ec get() = _algSpecific.defaultOption("EC",
    EphemeralSigningKeyConfigurationBase::ECConfiguration
)
val EphemeralSigningKeyConfigurationBase.rsa get() = _algSpecific.option("RSA",
    EphemeralSigningKeyConfigurationBase::RSAConfiguration
)

@Suppress("NOTHING_TO_INLINE")
expect class EphemeralSigningKeyConfiguration internal constructor(): EphemeralSigningKeyConfigurationBase

typealias EphemeralSignerConfigurationBase = SignerConfiguration

@Suppress("NOTHING_TO_INLINE")
expect class EphemeralSignerConfiguration internal constructor(): SignerConfiguration