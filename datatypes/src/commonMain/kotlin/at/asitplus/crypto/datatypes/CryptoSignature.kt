package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.BERTags.INTEGER
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Contextual
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable


/**
 * Data class which holds Asn1 Encoding of a signature of a specified algorithm
 * Allows simple ASN1 - Raw transformation of signature values
 * Does not check for anything!
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CryptoSignature(
    @Contextual
    val signature: Asn1Sequence,
    val algorithm: JwsAlgorithm
) {
    fun serialize() = derEncoded.encodeToString(Base64UrlStrict)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CryptoSignature

        if (signature != other.signature) return false
        if (algorithm != other.algorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signature.hashCode()
        result = 31 * result + algorithm.hashCode()
        return result
    }

    val derEncoded by lazy { signature.derEncoded }

    /**
     * Removes ASN1 Structure and returns the value(s) as ByteArray
     */
    val rawByteArray by lazy {
        when (algorithm) {
            JwsAlgorithm.ES512, JwsAlgorithm.ES384, JwsAlgorithm.ES256 ->
                byteArrayOf(*(signature.children[0] as Asn1Primitive).content, *(signature.children[2] as Asn1Primitive).content)

            else -> TODO()
        }
    }

    companion object {
        fun fromRawByteArray(input: ByteArray, algorithm: JwsAlgorithm): CryptoSignature {
            val asn1string = when (algorithm) {
                JwsAlgorithm.ES256, JwsAlgorithm.ES384, JwsAlgorithm.ES512 ->
                    asn1Sequence {
                        append(
                            Asn1Primitive(
                                INTEGER,
                                input.sliceArray(0..(input.size / 2))
                            )
                        )
                        append(
                            Asn1Primitive(
                                INTEGER,
                                input.sliceArray((input.size / 2)..input.size)
                            )
                        )
                    }

                else -> TODO()
            }
            return CryptoSignature(asn1string, algorithm)
        }

        fun fromDerEncoded(input: ByteArray, algorithm: JwsAlgorithm): CryptoSignature {
            TODO()
        }
    }
}