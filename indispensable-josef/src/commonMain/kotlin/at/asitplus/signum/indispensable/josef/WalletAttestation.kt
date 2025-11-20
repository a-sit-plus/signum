package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class EudiWalletInfo(
    @SerialName("general_info") val generalInfo: GeneralInfo? = null,
    @SerialName("key_storage_info") val keyStorageInfo: KeyStorageInfo? = null,
)

@Serializable
data class GeneralInfo(
    @SerialName("wallet_provider_name") val walletProviderName: String,
    @SerialName("wallet_solution_id") val walletSolutionId: String,
    @SerialName("wallet_solution_version") val walletSolutionVersion: String,
    @SerialName("wallet_solution_certification_information") val walletSolutionCertificationInformation: String
)

@Serializable
data class KeyStorageInfo(
    @SerialName("storage_type") val storageType: String,
    @SerialName("storage_certification_information") val storageCertificationInformation: String,
)