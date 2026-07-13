package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.json.JsonObjectBackedSerializerTemplate
import at.asitplus.propigator.json.jsonProperty
import at.asitplus.signum.indispensable.josef.JwtBaseClaims
import at.asitplus.signum.indispensable.josef.JwtClaimNames.UnregisteredClaims
import at.asitplus.signum.indispensable.josef.JwtPayload
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.strictUnion
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*


@Serializable(with = ClientAttestationPopPayload.Serializer::class)
@Deprecated("Will move into VCK next release")
data class ClientAttestationPopPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JwtPayload(raw, json) {
    /**
     * Challenge is currently modeled as string
     */
    constructor(
        jwtBase: JwtBaseClaims,
        challenge: String,
        misc: Map<String, JsonElement>? = null,
        json: Json = joseCompliantSerializer
    ) : this(
        json.encodeToJsonElement(jwtBase).jsonObject
            .strictUnion(UnregisteredClaims.DraftIetfOauthAttestation.encodeChallenge(challenge,json))
            .strictUnion(misc?.let { JsonObject(it) })
    )

    val challenge: String? by jsonProperty(UnregisteredClaims.DraftIetfOauthAttestation.CHALLENGE)

    override fun validate() {
        jwtBaseClaims
        jwtBaseClaims.audience!!
        jwtBaseClaims.jwtId!!
        jwtBaseClaims.issuedAt!!
        challenge
    }

    object Serializer :
        KSerializer<ClientAttestationPopPayload> by JsonObjectBackedSerializerTemplate(::ClientAttestationPopPayload)

}

@Deprecated("Will move into VCK next release")
private fun UnregisteredClaims.DraftIetfOauthAttestation.encodeChallenge(challenge: String, json: Json): JsonObject = JsonObject(
    mapOf(this.CHALLENGE to json.encodeToJsonElement(challenge))
)
