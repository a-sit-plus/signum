package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decode

data class CertId @Throws(Asn1Exception::class) constructor(
    val hashAlgorithms: AlgorithmIdentifier,
    val issuerNameHash: ByteArray,
    val issuerKeyHash: ByteArray,
    val serialNumber: ByteArray
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +hashAlgorithms
        +Asn1Primitive(Asn1Element.Tag.OCTET_STRING, issuerNameHash)
        +Asn1Primitive(Asn1Element.Tag.OCTET_STRING, issuerKeyHash)
        +Asn1Primitive(Asn1Element.Tag.INT, serialNumber)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CertId

        if (hashAlgorithms != other.hashAlgorithms) return false
        if (!issuerNameHash.contentEquals(other.issuerNameHash)) return false
        if (!issuerKeyHash.contentEquals(other.issuerKeyHash)) return false
        if (!serialNumber.contentEquals(other.serialNumber)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hashAlgorithms.hashCode()
        result = 31 * result + issuerNameHash.contentHashCode()
        result = 31 * result + issuerKeyHash.contentHashCode()
        result = 31 * result + serialNumber.contentHashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, CertId> {
        override fun doDecode(src: Asn1Sequence): CertId {
            val hashAlg = AlgorithmIdentifier.decodeFromTlv(src.nextChild().asSequence())
            val nameHash = src.nextChild().asPrimitive().decode(Asn1Element.Tag.OCTET_STRING) { it }
            val keyHash = src.nextChild().asPrimitive().decode(Asn1Element.Tag.OCTET_STRING) { it }
            val serialNumber = src.nextChild().asPrimitive().decode(Asn1Element.Tag.INT) { it }
            return CertId(hashAlg, nameHash, keyHash, serialNumber)
        }
    }
}

data class AlgorithmIdentifier(
    override val oid: ObjectIdentifier,
    val parameters: Asn1Element
) : Identifiable, Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +oid
        +parameters
    }

    companion object : Asn1Decodable<Asn1Sequence, AlgorithmIdentifier> {
        override fun doDecode(src: Asn1Sequence): AlgorithmIdentifier =
            AlgorithmIdentifier(
                ObjectIdentifier.decodeFromTlv(src.nextChild().asPrimitive()),
                src.nextChild()
            )

    }

}