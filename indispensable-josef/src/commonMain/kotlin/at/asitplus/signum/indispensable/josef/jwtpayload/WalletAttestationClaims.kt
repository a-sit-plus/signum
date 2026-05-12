package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.signum.indispensable.josef.ClientStatus
import at.asitplus.signum.indispensable.josef.JwtClaims.IanaRegistered
import at.asitplus.signum.indispensable.josef.JwtClaims.UnregisteredClaims
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wallet Instance Attestation (WIA) as defined by
 * [EUDI TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
@Serializable
data class WalletAttestationClaims(

    /**
     * OID4VCI: OPTIONAL. String containing a human-readable name of the Wallet.
     * EUDI TS3 REQUIRED
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_NAME)
    val walletName: String,

    /**
     * OID4VCI: OPTIONAL. String containing a URL to get further information about the Wallet and the Wallet Provider.
     * EUDI TS3 OPTIONAL
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_LINK)
    val walletLink: String? = null,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED. version of the Wallet Solution.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_VERSION)
    val walletVersion: String,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED. information about the certification achieved by the Wallet Solution.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_SOLUTION_CERTIFICATION_INFORMATION)
    val walletSolutionCertificationInformation: String,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED.
     * status list reference for the Wallet Instance and the time until which the Wallet Provider
     * commits to maintaining the referenced status.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.CLIENT_STATUS)
    val clientStatus: ClientStatus,
)