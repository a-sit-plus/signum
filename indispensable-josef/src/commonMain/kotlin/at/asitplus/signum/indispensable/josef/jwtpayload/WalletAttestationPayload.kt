package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.common.ObjectBackedValidated
import at.asitplus.propigator.json.*
import at.asitplus.signum.indispensable.josef.JwtClaims
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject


@Serializable(with = WalletAttestationPayload.Serializer::class)
data class WalletAttestationPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JsonObjectBacked(raw, JsonBackingCodec(json)), ObjectBackedValidated {

    val jwtClaims: JwtClaims by jsonSlice()
    val walletAttestationClaims: WalletAttestationClaims by jsonSlice()

    override fun validate() {
        jwtClaims
        walletAttestationClaims
        jwtClaims.subject!!
        jwtClaims.expiration!!
    }

    object Serializer : KSerializer<WalletAttestationPayload> by JsonObjectBackedSerializer(::WalletAttestationPayload)
}
