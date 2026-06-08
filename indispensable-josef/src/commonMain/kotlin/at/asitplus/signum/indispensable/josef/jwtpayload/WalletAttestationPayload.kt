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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject


@Serializable(with = WalletAttestationPayload.Serializer::class)
data class WalletAttestationPayload(
    private val raw: JsonObject,
    private val json: Json = joseCompliantSerializer,
) : JsonObjectBacked(raw, JsonBackingCodec(json)), ObjectBackedValidated, JwtPayload {

    constructor(
        jwtBase: JwtBaseClaims,
        walletAttestationClaims: WalletAttestationClaims,
        misc: JsonObject,
    ) : this(
        joseCompliantSerializer.encodeToJsonElement(jwtBase).jsonObject
            .strictUnion(joseCompliantSerializer.encodeToJsonElement(walletAttestationClaims).jsonObject)
            .strictUnion(misc)
    )

    val jwtBaseClaims: JwtBaseClaims by jsonSlice()
    val walletAttestationClaims: WalletAttestationClaims by jsonSlice()

    override fun validate() {
        jwtBaseClaims
        walletAttestationClaims
        jwtBaseClaims.subject!!
        jwtBaseClaims.expiration!!
    }

    object Serializer : KSerializer<WalletAttestationPayload> by JsonObjectBackedSerializer(::WalletAttestationPayload)
}
