package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.common.NullWriteMode
import at.asitplus.propigator.common.ObjectBackedValidated
import at.asitplus.propigator.json.JsonBackingCodec
import at.asitplus.propigator.json.JsonObjectBacked
import at.asitplus.propigator.json.JsonObjectBackedSerializer
import at.asitplus.propigator.json.jsonSlice
import at.asitplus.propigator.json.nullableJsonProperty
import at.asitplus.signum.indispensable.josef.JwtClaims
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject


@Serializable(with = WalletAttestationJwtPayload.Serializer::class)
data class WalletAttestationJwtPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JsonObjectBacked(raw, JsonBackingCodec(json)), ObjectBackedValidated {

    val jwtClaims: JwtClaims by jsonSlice()
    val walletAttestationClaims: WalletAttestationClaims by jsonSlice()
    val nonce: String? by nullableJsonProperty<String>(
        JwtClaims.IanaRegistered.ClaimNames.OpenIdConnectCore.NONCE,
        NullWriteMode.REMOVE_KEY
    )

    override fun validate() {
        jwtClaims
        jwtClaims.issuedAt != null
        walletAttestationClaims
    }

    object Serializer : KSerializer<WalletAttestationJwtPayload> by JsonObjectBackedSerializer(::WalletAttestationJwtPayload)
}
