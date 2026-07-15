package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.json.JsonObjectBackedSerializerTemplate
import at.asitplus.propigator.json.jsonSlice
import at.asitplus.signum.indispensable.josef.JwtBaseClaims
import at.asitplus.signum.indispensable.josef.JwtPayload
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.strictUnion
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*


@Deprecated("Will move into VCK next release")
@Serializable(with = WalletAttestationPayload.Serializer::class)
class WalletAttestationPayload private constructor(
    raw: JsonObject,
    json: Json = joseCompliantSerializer
) : JwtPayload(raw, json) {

    /**
     * It is assumed that elements in [misc] are encoded correctly
     */
    constructor(
        jwtBase: JwtBaseClaims,
        walletAttestationClaims: WalletAttestationClaims,
        misc: Map<String, JsonElement>? = null,
        json: Json = joseCompliantSerializer
    ) : this(
        json.encodeToJsonElement(jwtBase).jsonObject
            .strictUnion(json.encodeToJsonElement(walletAttestationClaims).jsonObject)
            .strictUnion(misc?.let { JsonObject(it) })
    )

    val walletAttestationClaims: WalletAttestationClaims by jsonSlice()

    override fun validate() {
        jwtBaseClaims
        walletAttestationClaims
        jwtBaseClaims.subject!!
        jwtBaseClaims.expiration!!
    }

    object Serializer :
        KSerializer<WalletAttestationPayload> by JsonObjectBackedSerializerTemplate(::WalletAttestationPayload)
}
