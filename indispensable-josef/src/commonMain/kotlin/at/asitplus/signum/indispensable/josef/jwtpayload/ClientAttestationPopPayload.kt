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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject


@Serializable(with = ClientAttestationPopPayload.Serializer::class)
data class ClientAttestationPopPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JsonObjectBacked(raw, JsonBackingCodec(json)), ObjectBackedValidated, JwtPayload {

    /**
     * Challenge is currently modeled as string
     */
    constructor(
        jwtBase: JwtBaseClaims,
        challenge: String,
        misc: JsonObject,
    ) : this(
        joseCompliantSerializer.encodeToJsonElement(jwtBase).jsonObject
            .strictUnion(
                JsonObject(
                    mapOf(
                        UnregisteredClaims.DraftIetfOauthAttestation.CHALLENGE to JsonPrimitive(challenge)
                    )
                )
            )
            .strictUnion(misc)
    )

    val jwtBaseClaims: JwtBaseClaims by jsonSlice()
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
