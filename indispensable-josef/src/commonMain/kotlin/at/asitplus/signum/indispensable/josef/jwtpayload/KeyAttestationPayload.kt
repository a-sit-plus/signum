package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.common.ObjectBackedValidated
import at.asitplus.propigator.json.JsonBackingCodec
import at.asitplus.propigator.json.JsonObjectBacked
import at.asitplus.propigator.json.JsonObjectBackedSerializer
import at.asitplus.propigator.json.jsonSlice
import at.asitplus.signum.indispensable.josef.JwtBaseClaims
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.strictUnion
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Serializable(with = KeyAttestationPayload.Serializer::class)
data class KeyAttestationPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JwtPayload(raw, json), ObjectBackedValidated {

    constructor(
        jwtBase: JwtBaseClaims,
        keyAttestationClaims: KeyAttestationClaims,
        misc: Map<String, JsonElement>,
    ) : this(
        joseCompliantSerializer.encodeToJsonElement(jwtBase).jsonObject
            .strictUnion(joseCompliantSerializer.encodeToJsonElement(keyAttestationClaims).jsonObject)
            .strictUnion(JsonObject(misc))
    )

    val jwtBaseClaims: JwtBaseClaims by jsonSlice()
    val keyAttestationClaims: KeyAttestationClaims by jsonSlice()


    override fun validate() {
        jwtBaseClaims
        jwtBaseClaims.issuedAt!!
        keyAttestationClaims
    }

    object Serializer : KSerializer<KeyAttestationPayload> by JsonObjectBackedSerializer(::KeyAttestationPayload)
}
