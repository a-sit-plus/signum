package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.common.ObjectBackedValidated
import at.asitplus.propigator.json.*
import at.asitplus.signum.indispensable.josef.JwtBaseClaims
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.jwtpayload.JwtClaimNames.UnregisteredClaims
import at.asitplus.signum.indispensable.josef.strictUnion
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject


@Serializable(with = ClientAttestationPopPayload.Serializer::class)
data class ClientAttestationPopPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JwtPayload(raw, json), ObjectBackedValidated {

    /**
     * Challenge is currently modeled as string
     */
    constructor(
        jwtBase: JwtBaseClaims,
        challenge: String,
        misc: Map<String, JsonElement>,
    ) : this(
        joseCompliantSerializer.encodeToJsonElement(jwtBase).jsonObject
            .strictUnion(UnregisteredClaims.DraftIetfOauthAttestation.encodeChallenge(challenge))
            .strictUnion(JsonObject(misc))
    )

    val challenge: String? by nullableJsonProperty(UnregisteredClaims.DraftIetfOauthAttestation.CHALLENGE)

    override fun validate() {
        jwtBaseClaims
        jwtBaseClaims.audience!!
        jwtBaseClaims.jwtId!!
        jwtBaseClaims.issuedAt!!
        challenge
    }

    object Serializer :
        KSerializer<ClientAttestationPopPayload> by JsonObjectBackedSerializer(::ClientAttestationPopPayload)
}

private fun UnregisteredClaims.DraftIetfOauthAttestation.encodeChallenge(challenge: String): JsonObject = JsonObject(
    mapOf(this.CHALLENGE to joseCompliantSerializer.encodeToJsonElement(challenge))
)
