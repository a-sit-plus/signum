package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
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
        /**
         * Deserializes the input, expected to contain a valid JWS (three Base64-URL strings joined by `.`),
         * into a [JwsSigned] with `ByteArray` as the type of the payload.
         */
        inline fun deserialize(it: String): KmmResult<JwsSigned<ByteArray>> = catching {
            val stringList = it.parseTo3Parts()
            val inputParts = stringList.map { it.decodeToByteArray(Base64UrlStrict) }
            val header = inputParts[0].toJwsHeader()
            val payload = inputParts[1]
            val signature = inputParts[2].toSignature(header.algorithm.ecCurve)
            val plainSignatureInput = stringList[0] + "." + stringList[1]
            JwsSigned(header, payload, signature, plainSignatureInput)
        }

        /**
         * Deserializes the input, expected to contain a valid JWS (three Base64-URL strings joined by `.`),
         * into a [JwsSigned] with [P] as the type of the payload.
         */
        inline fun <reified P : Any> deserialize(it: String, json: Json = Json): KmmResult<JwsSigned<P>> = catching {
            val stringList = it.parseTo3Parts()
            val inputParts = stringList.map { it.decodeToByteArray(Base64UrlStrict) }
            val header = inputParts[0].toJwsHeader()
            val payload: P = inputParts[1].run { json.decodeFromString<P>(this.decodeToString()) }
            val signature = inputParts[2].toSignature(header.algorithm.ecCurve)
            val plainSignatureInput = stringList[0] + "." + stringList[1]
            JwsSigned(header, payload, signature, plainSignatureInput)
        }

        fun String.parseTo3Parts(): List<String> {
            val stringList = replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 3)
                throw IllegalArgumentException("not three parts in input: $this")
            return stringList
        }

        fun ByteArray.toJwsHeader(): JwsHeader =
            JwsHeader.deserialize(decodeToString())
                .mapFailure { it.apply { printStackTrace() } }
                .getOrThrow()

        fun ByteArray.toSignature(ecCurve: ECCurve?) =
            when (ecCurve) {
                null -> CryptoSignature.RSAorHMAC(this)
                else -> CryptoSignature.EC.fromRawBytes(ecCurve, this)
            }

        /**
         * Called by JWS signing implementations to get the string that will be
         * used as the input for signature calculation
         */
        @Suppress("unused")
        inline fun prepareJwsSignatureInput(
            header: JwsHeader,
            payload: ByteArray,
            json: Json = Json,
        ): String = "${header.serialize().encodeToByteArray().encodeToString(Base64UrlStrict)}" +
                ".${payload.encodeToString(Base64UrlStrict)}"

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

