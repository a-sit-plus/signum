package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * User Authentication types for the Wallet Attestation.
 *
 * See [OpenID4VC High Assurance Interoperability Profile with SD-JWT VC](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html#name-wallet-attestation-schema)
 */
@Serializable
@Deprecated("Removed in OID4VC HAIP")
enum class WalletAttestationUserAuthentication {
    /**  It MUST be used when the key usage is authorized by the mobile operating system using a biometric factor. */
    @SerialName("system_biometry")
    SYSTEM_BIOMETRY,

    /**
     * It MUST be used when the key usage is authorized by the mobile operating system using personal identification
     * number (PIN).
     */
    @SerialName("system_pin")
    SYSTEM_PIN,

    /** It MUST be used when the key usage is authorized by the Wallet using a biometric factor. */
    @SerialName("internal_biometry")
    INTERNAL_BIOMETRY,

    /** It MUST be used when the key usage is authorized by the Wallet using PIN. */
    @SerialName("internal_pin")
    INTERNAL_PIN,

    /** It MUST be used when the key usage is authorized by the secure element managing the key itself using PIN.*/
    @SerialName("secure_element_pin")
    SECURE_ELEMENT_PIN
}