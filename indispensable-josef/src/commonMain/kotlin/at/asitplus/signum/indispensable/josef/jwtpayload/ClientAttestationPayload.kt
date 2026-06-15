package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.common.ObjectBackedValidated
import at.asitplus.propigator.json.*
import at.asitplus.signum.indispensable.josef.JwtBaseClaims
import at.asitplus.signum.indispensable.josef.JwtPayload
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered
import at.asitplus.signum.indispensable.josef.strictUnion
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable(with = ClientAttestationPayload.Serializer::class)
@Deprecated("Will move into VCK next release")
data class ClientAttestationPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JwtPayload(raw, json), ObjectBackedValidated {

    constructor(
        jwtBase: JwtBaseClaims,
        confirmationClaim: ConfirmationClaim,
        misc: Map<String, JsonElement>,
    ) : this(
        joseCompliantSerializer.encodeToJsonElement(jwtBase).jsonObject
            .strictUnion(IanaRegistered.ClaimNames.RFC7800.encodeCNF(confirmationClaim))
            .strictUnion(JsonObject(misc))
    )

    /**
     * OID4VP: This claim contains the confirmation method as defined in RFC7800. It MUST contain a JWK as defined in
     * Section 3.2 of RFC7800. This claim determines the public key for which the corresponding private key the
     * Verifier MUST proof possession of when presenting the Verifier Attestation JWT. This additional security measure
     * allows the Verifier to obtain a Verifier Attestation JWT from a trusted issuer and use it for a long time
     * independent of that issuer without the risk of an adversary impersonating the Verifier by replaying a captured
     * attestation.
     */
    val confirmationClaim: ConfirmationClaim by jsonProperty(IanaRegistered.ClaimNames.RFC7800.CNF)

    override fun validate() {
        jwtBaseClaims
        jwtBaseClaims.subject!!
        jwtBaseClaims.expiration!!
        confirmationClaim
    }

    object Serializer : KSerializer<ClientAttestationPayload> by JsonObjectBackedSerializer(::ClientAttestationPayload)
}

@Deprecated("Will move into VCK next release")
private fun IanaRegistered.ClaimNames.RFC7800.encodeCNF(cnf: ConfirmationClaim): JsonObject = JsonObject(
    mapOf(this.CNF to joseCompliantSerializer.encodeToJsonElement(cnf))
)
