package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt

/**
 * Secure key import data structure
 */
class SecureKeyWrapper(
    val wrapperFormatVersion: Int = 0,
    val encryptedTransportKey: ByteArray,
    val initializationVector: ByteArray,
    val keyDescription: KeyDescription,
    val secureKey: ByteArray,
    /**AEAD authTag*/
    val tag: ByteArray
) : Asn1Encodable<Asn1Sequence> {
    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(wrapperFormatVersion)
        +Asn1.OctetString(encryptedTransportKey)
        +Asn1.OctetString(initializationVector)
        +keyDescription
        +Asn1.OctetString(secureKey)
        +Asn1.OctetString(tag)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecureKeyWrapper) return false

        if (wrapperFormatVersion != other.wrapperFormatVersion) return false
        if (!encryptedTransportKey.contentEquals(other.encryptedTransportKey)) return false
        if (!initializationVector.contentEquals(other.initializationVector)) return false
        if (keyDescription != other.keyDescription) return false
        if (!secureKey.contentEquals(other.secureKey)) return false
        if (!tag.contentEquals(other.tag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = wrapperFormatVersion
        result = 31 * result + encryptedTransportKey.contentHashCode()
        result = 31 * result + initializationVector.contentHashCode()
        result = 31 * result + keyDescription.hashCode()
        result = 31 * result + secureKey.contentHashCode()
        result = 31 * result + tag.contentHashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, SecureKeyWrapper> {
        override fun doDecode(src: Asn1Sequence) = SecureKeyWrapper(
            src.nextChild().asPrimitive().decodeToInt(),
            src.nextChild().asOctetString().content,
            src.nextChild().asOctetString().content,
            KeyDescription.decodeFromTlv(src.nextChild().asSequence()),
            src.nextChild().asOctetString().content,
            src.nextChild().asOctetString().content,
        ) //more content is OK. This way we allow future versions which may add stuff to work
    }
}

class KeyDescription(
    val keyFormat: KeyFormat,
    val authorizationList: AuthorizationList
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +keyFormat
        +authorizationList
    }

    enum class KeyFormat(val intValue: Int) : Asn1Encodable<Asn1Primitive> {
        X509(0),
        PKCS8(1),
        RAW(3);

        override fun encodeToTlv() = Asn1.Int(intValue)

        companion object : Asn1Decodable<Asn1Primitive, KeyFormat> {
            fun valueOf(int: Int) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToInt())
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, KeyDescription> {
        override fun doDecode(src: Asn1Sequence) = KeyDescription(
            KeyFormat.decodeFromTlv(src.nextChild().asPrimitive()),
            AuthorizationList.decodeFromTlv(src.nextChild().asSequence())
        ) //more content is OK. This way we allow future versions which may add stuff to work
    }
}