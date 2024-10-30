package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json

/**
 * Representation of a signed JSON Web Signature object, i.e. consisting of header, payload and signature.
 *
 * `<P>` represents the type of the payload.
 *
 * See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
 */
data class JwsSigned<out P : Any>(
    val header: JwsHeader,
    val payload: P,
    val signature: CryptoSignature.RawByteEncodable,
    val plainSignatureInput: String,
) {

    fun serialize(): String {
        return "${plainSignatureInput}.${signature.rawByteArray.encodeToString(Base64UrlStrict)}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsSigned<*>

        if (header != other.header) return false
        if (!payload.equals(other.payload)) return false
        return signature == other.signature
    }

    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + payload.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    override fun toString(): String {
        return "JwsSigned(header=$header" +
                ", payload=${payload}" +
                ", signature=$signature" +
                ", plainSignatureInput='$plainSignatureInput')"
    }


    companion object {
        inline fun <reified P : Any> deserialize(it: String, json: Json = Json): KmmResult<JwsSigned<P>> = catching {
            val stringList = it.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 3) throw IllegalArgumentException("not three parts in input: $it")
            val headerInput = stringList[0].decodeToByteArray(Base64UrlStrict)
            val header = JwsHeader.deserialize(headerInput.decodeToString())
                .mapFailure { it.apply { printStackTrace() } }
                .getOrThrow()
            val payload: P = json.decodeFromString<P>(stringList[1].decodeToByteArray(Base64UrlStrict).decodeToString())
            val signature = stringList[2].decodeToByteArray(Base64UrlStrict)
                .let { bytes ->
                    when (val curve = header.algorithm.ecCurve) {
                        null -> CryptoSignature.RSAorHMAC(bytes)
                        else -> CryptoSignature.EC.fromRawBytes(curve, bytes)
                    }
                }
            val plainSignatureInput = stringList[0] + "." + stringList[1]
            JwsSigned(header, payload, signature, plainSignatureInput)
        }


        /**
         * Called by JWS signing implementations to get the string that will be
         * used as the input for signature calculation
         */
        @Suppress("unused")
        inline fun <T : Any> prepareJwsSignatureInput(
            header: JwsHeader,
            payload: T,
            serializer: SerializationStrategy<T>,
            json: Json = Json,
        ): String = "${header.serialize().encodeToByteArray().encodeToString(Base64UrlStrict)}" +
                ".${json.encodeToString(serializer, payload).encodeToByteArray().encodeToString(Base64UrlStrict)}"
    }
}

