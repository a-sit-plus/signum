package at.asitplus.signum.dsl

class IosSecureEnclaveConfiguration internal constructor() : PlatformSigningKeyConfigurationBase.SecureHardwareConfiguration() {
    /** Set to true to allow this key to be backed up. */
    var allowBackup = false
    enum class Availability { ALWAYS, AFTER_FIRST_UNLOCK, WHILE_UNLOCKED }
    /** Specify when this key should be available */
    var availability = Availability.ALWAYS
}

class IosSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfigurationBase<IosSignerConfiguration>()

val IosSigningKeyConfiguration.hardware get() =
    childOrDefault("HARDWARE", ::IosSecureEnclaveConfiguration) {
        backing = DISCOURAGED
    }

class IosSignerConfiguration internal constructor(): PlatformSignerConfigurationBase()
typealias IosSignerSigningConfiguration = PlatformSigningProviderSignerSigningConfigurationBase