package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray

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
    val algorithm: CoseAlgorithm.Hash,
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
