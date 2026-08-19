package at.asitplus.signum.dsl

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import at.asitplus.signum.supreme.dsl.FeaturePreference
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.dsl.REQUIRED
import at.asitplus.signum.supreme.dsl.DISCOURAGED
import at.asitplus.signum.supreme.os.FragmentContext

class AndroidKeymasterConfiguration internal constructor(): PlatformSigningKeyConfigurationBase.SecureHardwareConfiguration() {
    /**
     * Whether to back this key with a StrongBox secure element.
     * - [REQUIRED]: use StrongBox; key generation fails if the device lacks StrongBox or the algorithm/params are unsupported.
     * - [PREFERRED] (default): use StrongBox if available and it supports the requested algorithm/params,
     *   otherwise transparently fall back to the TEE.
     * - [DISCOURAGED]: do not use StrongBox.
     * @see FeaturePreference
     */
    var strongBox: FeaturePreference = PREFERRED
}

class AndroidSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfigurationBase<AndroidSignerConfiguration>()

class AndroidUnlockPromptConfiguration internal constructor(): UnlockPromptConfiguration() {
    /** Explicitly specify the FragmentActivity to use for authentication prompts.
     * You will not need to set this in most cases; the default is the current activity. */
    lateinit var activity: FragmentActivity

    /** Explicitly set the Fragment to base authentication prompts on.
     * You will not need to set this in most cases; the default is the current activity.*/
    lateinit var fragment: Fragment

    internal val explicitContext: FragmentContext
        get() = when {
        this::fragment.isInitialized -> FragmentContext.OfFragment(fragment)
        else                         -> FragmentContext.OfActivity(activity)
    }
    internal val hasExplicitContext get() =
        (this::fragment.isInitialized || this::activity.isInitialized)

    internal val _subtitle = Stackable<String?>()
    /** @see [androidx.biometric.BiometricPrompt.PromptInfo.Builder.setSubtitle] */
    var subtitle by _subtitle

    internal val _description = Stackable<String?>()
    /** @see [androidx.biometric.BiometricPrompt.PromptInfo.Builder.setDescription] */
    var description by _description

    internal val _confirmationRequired = Stackable<Boolean?>()
    /** @see [androidx.biometric.BiometricPrompt.PromptInfo.Builder.setConfirmationRequired] */
    var confirmationRequired by _confirmationRequired

    internal val _allowedAuthenticators = Stackable<Int?>()
    /** @see [androidx.biometric.BiometricPrompt.PromptInfo.Builder.setAllowedAuthenticators] */
    var allowedAuthenticators by _allowedAuthenticators

    /** if the provided fingerprint could not be matched, but the user will be allowed to retry */
    var invalidBiometryCallback: (()->Unit)? = null
}

class AndroidSignerConfiguration: PlatformSignerConfigurationBase()

class AndroidSignerSigningConfiguration: PlatformSigningProviderSignerSigningConfigurationBase()