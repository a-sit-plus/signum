package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class containing information for instance/unit attestation
 * which are not part of the OID4VCI specification.
 * See https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
 */
@Serializable
data class EudiWalletInfo(
    @SerialName("general_info") val generalInfo: GeneralInfo? = null,
    @SerialName("key_storage_info") val keyStorageInfo: KeyStorageInfo? = null,
)

/**
 * Data class specifying general information on the wallet unit
 * See https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
 */
@Serializable
data class GeneralInfo(
    @SerialName("wallet_provider_name") val walletProviderName: String,
    @SerialName("wallet_solution_id") val walletSolutionId: String,
    @SerialName("wallet_solution_version") val walletSolutionVersion: String,
    @SerialName("wallet_solution_certification_information") val walletSolutionCertificationInformation: String
)

/**
 * Data class specifying information on the key storage containing the attested keys.
 * See https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
 */
@Serializable
data class KeyStorageInfo(
    @SerialName("storage_type") val storageType: String,
    @SerialName("storage_certification_information") val storageCertificationInformation: String,
)