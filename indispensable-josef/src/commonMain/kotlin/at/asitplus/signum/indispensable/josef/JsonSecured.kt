package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Parent class of Json formats that either use [JWS] or [JWE]
 * If payload is [JwtBaseClaims] and either [JwsCompact] and/or [JweCompact] is used then this is a JsonWebToken.
 */
@Serializable(with = JsonSecuredSerializer::class)
sealed interface JsonSecured

suspend inline fun <reified P> JsonSecured.getPayload(noinline decryptor: decryptorFun? = null): KmmResult<P> =
    when (this) {
        is JWS -> getPayload<P>()
        is JWE -> decryptor?.let { getPayload<P>(it) } ?: KmmResult(Exception("No Decryptor provided"))
    }
