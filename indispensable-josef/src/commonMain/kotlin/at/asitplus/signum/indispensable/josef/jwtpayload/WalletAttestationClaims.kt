package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.signum.indispensable.josef.ClientStatus
import at.asitplus.signum.indispensable.josef.JwtClaims.IanaRegistered
import at.asitplus.signum.indispensable.josef.JwtClaims.UnregisteredClaims
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class WalletAttestationClaims(
    /**
     * OID4VP: This claim contains the confirmation method as defined in RFC7800. It MUST contain a JWK as defined in
     * Section 3.2 of RFC7800. This claim determines the public key for which the corresponding private key the
     * Verifier MUST proof possession of when presenting the Verifier Attestation JWT. This additional security measure
     * allows the Verifier to obtain a Verifier Attestation JWT from a trusted issuer and use it for a long time
     * independent of that issuer without the risk of an adversary impersonating the Verifier by replaying a captured
     * attestation.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7800.CNF)
    val confirmationClaim: ConfirmationClaim? = null,

    /**
     * OID4VCI: OPTIONAL. String containing a human-readable name of the Wallet.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_NAME)
    val walletName: String? = null,

    /**
     * OID4VCI: OPTIONAL. String containing a URL to get further information about the Wallet and the Wallet Provider.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_LINK)
    val walletLink: String? = null,

    /**
     * EUDI TS3 WUA 1.5: version of the Wallet Solution.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_VERSION)
    val walletVersion: String? = null,

    /**
     * EUDI TS3 WUA 1.5: information about the certification achieved by the Wallet Solution.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_SOLUTION_CERTIFICATION_INFORMATION)
    val walletSolutionCertificationInformation: String? = null,

    /**
     * EUDI TS3 WUA 1.5: status list reference for the Wallet Instance and the time until which the Wallet Provider
     * commits to maintaining the referenced status.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.CLIENT_STATUS)
    val clientStatus: ClientStatus? = null,
)