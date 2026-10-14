package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray

/**
 * One signer entry of a `COSE_Sign`. See
 * [RFC 9052 §4.1](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.1).
 *
 * ```
 * COSE_Signature = [ Headers, signature: bstr ]
 * ```
 *
 * The analogue of josef's `SignatureElement`: a signature plus *its own* header buckets, carried alongside the
 * body's buckets. Each signer's `Sig_structure` therefore covers five elements — the body's protected bucket and
 * the signer's — which is why [signatureInput] takes the body bucket as a parameter.
 *
 * Either bucket may be partial; only the combination has to form a usable [CoseHeader].
 *
 * Introduced ahead of `COSE_Sign` itself so that the multi-signer type can be added without reshaping this one.
 */
@ConsistentCopyVisibility
@Serializable
@CborArray
data class CoseSignature internal constructor(
    /** This signer's `protected` bucket as transmitted. Empty array = zero-length `bstr`. */
    @ByteString
    val plainProtectedHeader: ByteArray,

    /** This signer's `unprotected` bucket. */
    val unprotectedHeader: CoseHeader?,

    /** The signature `bstr`. */
    @ByteString
    val plainSignature: ByteArray,
) {

    /** Typed view of [plainProtectedHeader]. */
    @Transient
    val protectedHeader: CoseHeader = COSE.decodeProtectedHeader(plainProtectedHeader)

    @Transient
    val signature: CryptoSignature =
        COSE.getSignature(plainSignature, protectedHeader, unprotectedHeader)

    /**
     * The five-element `Sig_structure` this signer's [signature] is computed over.
     *
     * @param bodyProtectedHeader the enclosing `COSE_Sign`'s protected bucket, as transmitted
     */
    fun signatureInput(
        bodyProtectedHeader: ByteArray,
        externalAad: ByteArray = byteArrayOf(),
        payload: ByteArray?,
    ): ByteArray = COSE.signerStructureInput(
        bodyProtectedHeader = bodyProtectedHeader,
        signProtectedHeader = plainProtectedHeader,
        externalAad = externalAad,
        payload = payload,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSignature

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!plainSignature.contentEquals(other.plainSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader.contentHashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }

    override fun toString(): String = "CoseSignature(" +
            "protectedHeader=$protectedHeader, " +
            "unprotectedHeader=$unprotectedHeader, " +
            "signature=${plainSignature.encodeToString(Base16Strict)})"

    companion object {

        operator fun invoke(
            plainProtectedHeader: ByteArray,
            unprotectedHeader: CoseHeader? = null,
            plainSignature: ByteArray,
        ): CoseSignature = CoseSignature(plainProtectedHeader, unprotectedHeader, plainSignature)

        /**
         * Encodes [protectedHeader] once and returns both the bytes to keep and the structure to sign, mirroring
         * [CoseSign1.Companion.prepare].
         */
        fun prepare(
            protectedHeader: CoseHeader,
            bodyProtectedHeader: ByteArray,
            externalAad: ByteArray = byteArrayOf(),
            plainPayload: ByteArray?,
        ): CoseSign1.Companion.Prepared {
            val plainProtectedHeader = COSE.encodeProtectedHeader(protectedHeader)
            return CoseSign1.Companion.Prepared(
                plainProtectedHeader = plainProtectedHeader,
                signatureInput = COSE.signerStructureInput(
                    bodyProtectedHeader = bodyProtectedHeader,
                    signProtectedHeader = plainProtectedHeader,
                    externalAad = externalAad,
                    payload = plainPayload,
                ),
            )
        }
    }
}