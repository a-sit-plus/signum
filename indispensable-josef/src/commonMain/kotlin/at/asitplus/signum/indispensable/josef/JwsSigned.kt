package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.DeserializationStrategy
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
    val plainSignatureInput: ByteArray,
) {

    fun serialize(): String {
        return "${plainSignatureInput.decodeToString()}.${signature.rawByteArray.encodeToString(Base64UrlStrict)}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsSigned<*>

        if (header != other.header) return false
        if (!payload.contentEqualsIfArray(other.payload)) return false
        return signature == other.signature
    }

    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + payload.contentHashCodeIfArray()
        result = 31 * result + signature.hashCode()
        return result
    }

    override fun toString(): String {
        return "JwsSigned(header=$header" +
                ", payload=${payload}" +
                ", signature=$signature" +
                ", plainSignatureInput='${plainSignatureInput.decodeToString()}')"
    }


    companion object {
        /**
         * Deserializes the input, expected to contain a valid JWS (three Base64-URL strings joined by `.`),
         * into a [JwsSigned] with [ByteArray] as the type of the payload.
         */
        @Suppress("NOTHING_TO_INLINE")
        inline fun deserialize(input: String): KmmResult<JwsSigned<ByteArray>> = catching {
            val stringList = input.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 3)
                throw IllegalArgumentException("not three parts in input: $this")
            val inputParts = stringList.map { it.decodeToByteArray(Base64UrlStrict) }
            val header = with(inputParts[0]) {
                JwsHeader.deserialize(decodeToString())
                    .mapFailure { it.apply { printStackTrace() } }
                    .getOrThrow()
            }
            val payload = inputParts[1]
            val signature = with(inputParts[2]) {
                when (val alg = header.algorithm) {
                    is JwsAlgorithm.Signature.EC -> CryptoSignature.EC.fromRawBytes(alg.ecCurve, this)
                    is JwsAlgorithm.Signature.RSA -> CryptoSignature.RSA(this)
                    else -> throw IllegalArgumentException("unsupported algorithm: $alg")
                }

            }
            val plainSignatureInput = (stringList[0] + "." + stringList[1]).encodeToByteArray()
            JwsSigned(header, payload, signature, plainSignatureInput)
        }

        /**
         * Deserializes the input, expected to contain a valid JWS (three Base64-URL strings joined by `.`),
         * into a [JwsSigned] with [P] as the type of the payload.
         */
        inline fun <reified P : Any> deserialize(
            deserializationStrategy: DeserializationStrategy<P>,
            it: String,
            json: Json = Json,
        ): KmmResult<JwsSigned<P>> =
            deserialize(it).mapCatching {
                JwsSigned(
                    header = it.header,
                    payload = json.decodeFromString(deserializationStrategy, it.payload.decodeToString()),
                    signature = it.signature,
                    plainSignatureInput = it.plainSignatureInput
                )
            }

        /**
         * Called by JWS signing implementations to get the string that will be
         * used as the input for signature calculation
         */
        @Suppress("unused")
        fun prepareJwsSignatureInput(header: JwsHeader, payload: ByteArray): ByteArray =
            (header.serialize().encodeToByteArray().encodeToString(Base64UrlStrict) +
                    ".${payload.encodeToString(Base64UrlStrict)}").encodeToByteArray()

        /**
         * Called by JWS signing implementations to get the string that will be
         * used as the input for signature calculation
         */
        @Suppress("unused", "NOTHING_TO_INLINE")
        inline fun <T : Any> prepareJwsSignatureInput(
            header: JwsHeader,
            payload: T,
            serializer: SerializationStrategy<T>,
            json: Json = Json,
        ): ByteArray = prepareJwsSignatureInput(header, json.encodeToString(serializer, payload).encodeToByteArray())
    }
}

