package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.common.NullWriteMode
import at.asitplus.propigator.common.ObjectBackedValidated
import at.asitplus.propigator.json.*
import at.asitplus.signum.indispensable.josef.JwtClaims
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

@Serializable(with = KeyAttestationPayload.Serializer::class)
data class KeyAttestationPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JsonObjectBacked(raw, JsonBackingCodec(json)), ObjectBackedValidated {

    val jwtClaims: JwtClaims by jsonSlice()
    val keyAttestationClaims: KeyAttestationClaims by jsonSlice()
    val nonce: String? by nullableJsonProperty<String>(
        JwtClaims.IanaRegistered.ClaimNames.OpenIdConnectCore.NONCE,
        NullWriteMode.REMOVE_KEY
    )

    override fun validate() {
        jwtClaims
        keyAttestationClaims
    }

    object Serializer : KSerializer<KeyAttestationPayload> by JsonObjectBackedSerializer(::KeyAttestationPayload)
}

