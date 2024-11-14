package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Key types for the Wallet Attestation.
 *
 * See [OpenID4VC High Assurance Interoperability Profile with SD-JWT VC](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html#name-wallet-attestation-schema)
 */
@Serializable
enum class WalletAttestationKeyType {
    /** It MUST be used when the Wallet uses software-based key management. */
    @SerialName("software")
    SOFTWARE,

    /** It MUST be used when the wallet uses hardware-based key management. */
    @SerialName("hardware")
    HARDWARE,

    /** It SHOULD be used when the Wallet uses the Trusted Execution Environment for key management. */
    @SerialName("tee")
    TEE,

    /** It SHOULD be used when the Wallet uses the Secure Enclave for key management. */
    @SerialName("secure_enclave")
    SECURE_ENCLAVE,

    /** It SHOULD be used when the Wallet uses the Strongbox for key management. */
    @SerialName("strong_box")
    STRONG_BOX,

    /** It SHOULD be used when the Wallet uses a Secure Element for key management. */
    @SerialName("secure_element")
    SECURE_ELEMENT,

    /** It SHOULD be used when the Wallet uses Hardware Security Module (HSM). */
    @SerialName("hsm")
    HSM
}