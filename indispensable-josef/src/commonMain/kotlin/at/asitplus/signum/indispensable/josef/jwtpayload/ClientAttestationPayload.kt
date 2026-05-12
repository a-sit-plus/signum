package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.common.ObjectBackedValidated
import at.asitplus.propigator.json.JsonBackingCodec
import at.asitplus.propigator.json.JsonObjectBacked
import at.asitplus.propigator.json.JsonObjectBackedSerializer
import at.asitplus.propigator.json.jsonProperty
import at.asitplus.propigator.json.jsonSlice
import at.asitplus.signum.indispensable.josef.JwtClaims
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

@Serializable(with = ClientAttestationPayload.Serializer::class)
data class ClientAttestationPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JsonObjectBacked(raw, JsonBackingCodec(json)), ObjectBackedValidated {
    val jwtClaims: JwtClaims by jsonSlice()
    val confirmation: ConfirmationClaim by jsonProperty(JwtClaims.IanaRegistered.ClaimNames.RFC7800.CNF)
    override fun validate() {
        jwtClaims
        jwtClaims.subject!!
        jwtClaims.expiration!!
        confirmation
    }

    object Serializer : KSerializer<ClientAttestationPayload> by JsonObjectBackedSerializer(::ClientAttestationPayload)
}