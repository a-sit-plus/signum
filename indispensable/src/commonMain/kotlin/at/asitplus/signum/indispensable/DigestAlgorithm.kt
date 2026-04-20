package at.asitplus.signum.indispensable

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Null
import at.asitplus.signum.indispensable.asn1.Asn1OidException
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1Structure
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.readOid
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

private interface DigestAlgorithmProvider {
    fun loaderForOid(oid: ObjectIdentifier): ((Asn1Structure.Iterator) -> DigestAlgorithm)?
}
// TODO Identical class as X509SignatureAlgorithmDescription b
//  Both represented as AlgorithmIdentifier ASN.1 structure (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2)
sealed class DigestAlgorithmDescription(
    override val oid: ObjectIdentifier,
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    abstract val parameters: Asn1Element?

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        parameters?.let { +it }
    }

    internal class Unknown(
        oid: ObjectIdentifier,
        override val parameters: Asn1Element?
    ) : DigestAlgorithmDescription(oid)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DigestAlgorithmDescription) return false
        return oid == other.oid && parameters == other.parameters
    }

    override fun hashCode(): Int =
        31 * oid.hashCode() + (parameters?.hashCode() ?: 0)


    companion object : Asn1Decodable<Asn1Sequence, DigestAlgorithmDescription> {
        override fun doDecode(src: Asn1Sequence) = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()

            sequenceOf<DigestAlgorithmProvider>(DigestAlgorithm.Provider)
                .firstNotNullOfOrNull { it.loaderForOid(oid) }
                ?.invoke(this@decodeRethrowing)
                ?: run {
                    val p = if (hasNext()) next() else null
                    Unknown(oid, p)
                }
        }
    }
}

/** smart-casts the receiver to an [DigestAlgorithm.Supported] if supported.*/
@OptIn(ExperimentalContracts::class)
fun DigestAlgorithmDescription.isSupported(): Boolean {
    contract {
            returns(true) implies (this@isSupported is DigestAlgorithm)
    }
    return (this is DigestAlgorithm)
}

/** throws if the [DigestAlgorithm] is unsupported */
@OptIn(ExperimentalContracts::class)
fun DigestAlgorithmDescription.requireSupported() {
    contract {
        returns() implies (this@requireSupported is DigestAlgorithm)
    }
    if (this !is DigestAlgorithm) throw UnsupportedCryptoException("Unsupported X.509 hash algorithm (OID = ${this.oid})")
}

sealed class DigestAlgorithm(
    override val oid: ObjectIdentifier,
    override val digest: Digest,
) : DigestAlgorithmDescription(oid), SpecializedDigestAlgorithm {
//    TODO: make immutable
    override var parameters: Asn1Element? = Asn1Null

    internal object Provider : DigestAlgorithmProvider {
        override fun loaderForOid(oid: ObjectIdentifier): ((Asn1Structure.Iterator) -> DigestAlgorithm)? {
            val algorithm = fromOid(oid) ?: return null

            return { iter ->
                val param = if (iter.hasNext()) iter.next() else null

                if (param != null && param != Asn1Null) {
                    throw Asn1TagMismatchException(
                        Asn1Element.Tag.NULL,
                        param.tag,
                        "Expected NULL or no parameters"
                    )
                }
                algorithm.parameters = param
                algorithm
            }
        }
    }

    object SHA1 : DigestAlgorithm(Digest.SHA1.oid, Digest.SHA1)
    object SHA256 : DigestAlgorithm(Digest.SHA256.oid, Digest.SHA256)
    object SHA384 : DigestAlgorithm(Digest.SHA384.oid, Digest.SHA384)
    object SHA512 : DigestAlgorithm(Digest.SHA512.oid, Digest.SHA512)

    companion object : Asn1Decodable<Asn1Sequence, DigestAlgorithm> {

        val entries by lazy {
            setOf(
                SHA1, SHA256, SHA384, SHA512
            )
        }

        private fun fromOid(oid: ObjectIdentifier) =
            entries.firstOrNull { it.oid == oid }

        override fun doDecode(src: Asn1Sequence): DigestAlgorithm =
            DigestAlgorithmDescription.doDecode(src).let {
                it as? DigestAlgorithm
                    ?: throw Asn1OidException(
                        "Unsupported digest algorithm OID: ${it.oid}",
                        it.oid
                    )
            }

    }
}