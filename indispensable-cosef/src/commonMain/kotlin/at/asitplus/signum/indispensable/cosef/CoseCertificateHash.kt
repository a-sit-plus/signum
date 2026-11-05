package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.decodeIntOrText
import at.asitplus.signum.indispensable.digest.Digest
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Hash of an X.509 certificate, the `COSE_CertHash` used by the `x5t` header parameter:
 *
 * ```
 * COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]
 * ```
 *
 * See [RFC 9360, Section 2](https://www.rfc-editor.org/rfc/rfc9360.html#section-2).
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
@CborArray
data class CoseCertificateHash(
    /** Hash algorithm, from the IANA "COSE Algorithms" registry. */
    val algorithm: CoseHashAlgorithm,
    /** Hash value computed over the DER-encoded certificate. */
    @ByteString
    val hashValue: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        other as CoseCertificateHash
        return algorithm == other.algorithm && hashValue.contentEquals(other.hashValue)
    }

    override fun hashCode(): Int = 31 * algorithm.hashCode() + hashValue.contentHashCode()

    override fun toString(): String =
        "CoseCertificateHash(algorithm=$algorithm, hashValue=${hashValue.encodeToString(Base16Strict)})"
}

/**
 * Hash algorithm of a [CoseCertificateHash], identified by an integer or a text string.
 *
 * See [RFC 9054, Section 2](https://www.rfc-editor.org/rfc/rfc9054.html#section-2) for the registered values.
 */
@Serializable(with = CoseHashAlgorithmSerializer::class)
sealed interface CoseHashAlgorithm {

    /** The corresponding [Digest], or `null` if not supported. */
    val digest: Digest?

    /** Algorithm identified by an integer value from the IANA "COSE Algorithms" registry. */
    sealed class Numeric(val coseValue: Int, override val digest: Digest?) : CoseHashAlgorithm

    data object SHA256 : Numeric(-16, Digest.SHA256)
    data object SHA384 : Numeric(-43, Digest.SHA384)
    data object SHA512 : Numeric(-44, Digest.SHA512)

    /** Any other integer value, e.g. SHA-1 (-14) or SHA-256/64 (-15), which have no [digest]. */
    class OtherNumeric(coseValue: Int) : Numeric(coseValue, null) {
        override fun equals(other: Any?) = other is OtherNumeric && other.coseValue == coseValue
        override fun hashCode() = coseValue
        override fun toString() = "OtherNumeric($coseValue)"
    }

    /** Algorithm identified by a text string, which has no [digest]. */
    data class Text(val name: String) : CoseHashAlgorithm {
        override val digest: Digest? get() = null
    }

    companion object {
        val entries: Collection<Numeric> by lazy { setOf(SHA256, SHA384, SHA512) }

        fun fromCoseValue(coseValue: Int): Numeric =
            entries.firstOrNull { it.coseValue == coseValue } ?: OtherNumeric(coseValue)
    }
}

object CoseHashAlgorithmSerializer : KSerializer<CoseHashAlgorithm> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseHashAlgorithm", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: CoseHashAlgorithm) = when (value) {
        is CoseHashAlgorithm.Numeric -> encoder.encodeInt(value.coseValue)
        is CoseHashAlgorithm.Text -> encoder.encodeString(value.name)
    }

    override fun deserialize(decoder: Decoder): CoseHashAlgorithm =
        decoder.decodeIntOrText({ CoseHashAlgorithm.fromCoseValue(it) }, { CoseHashAlgorithm.Text(it) })
}
