package at.asitplus.crypto.datatypes.jws

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * Representation of a signed JSON Web Signature object, i.e. consisting of header, payload and signature.
 *
 * See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
 */
data class JwsSigned(
    val header: JwsHeader,
    val payload: ByteArray,
    val signature: CryptoSignature.RawByteEncodable,
    val plainSignatureInput: String,
) {

    fun serialize(): String {
        return "${plainSignatureInput}.${signature.rawByteArray.encodeToString(Base64UrlStrict)}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsSigned

        if (header != other.header) return false
        if (!payload.contentEquals(other.payload)) return false
        return signature == other.signature
    }

    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    override fun toString(): String {
        return "JwsSigned(header=$header" +
                ", payload=${payload.encodeToString(Base64UrlStrict)}" +
                ", signature=$signature" +
                ", plainSignatureInput='$plainSignatureInput')"
    }


    companion object {
        fun parse(it: String): KmmResult<JwsSigned> = catching {
            val stringList = it.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 3) throw IllegalArgumentException("not three parts in input: $it")
            val headerInput = stringList[0].decodeToByteArray(Base64UrlStrict)
            val header =
                JwsHeader.deserialize(headerInput.decodeToString()).mapFailure { it.apply { printStackTrace() } }
                    .getOrThrow()
            val payload = stringList[1].decodeToByteArray(Base64UrlStrict)
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
        fun prepareJwsSignatureInput(header: JwsHeader, payload: ByteArray): String =
            "${header.serialize().encodeToByteArray().encodeToString(Base64UrlStrict)}" +
                    ".${payload.encodeToString(Base64UrlStrict)}"
    }
}

