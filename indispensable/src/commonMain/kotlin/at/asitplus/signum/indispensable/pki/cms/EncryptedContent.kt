/**
 * Inspired by CMS AuthEnvelopedData, but reduced to the bare essentials of a data container, s.t. the output still remains CMS compliant
 */
package at.asitplus.signum.indispensable.pki.cms

import at.asitplus.signum.indispensable.asn1.Asn1
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1OidException
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.DERTags.toImplicitTag
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.readInt

//TODO: refactor base classes to have a proper "AlgorithmIdentifier"

data class EncryptedContentInfo( //TODO Jakob: make it sealed and the child classes have a fixed contentEncryptionAlgorithm for your needs as per
    val contentEncryptionAlgorithm: Asn1Sequence,
    val encryptedContent: ByteArray
) : Asn1Encodable<Asn1Sequence> {

    @Throws(Asn1Exception::class)
    override fun encodeToTlv(): Asn1Sequence =
        Asn1.Sequence {
            +KnownOIDs.authEnvelopedData
            +contentEncryptionAlgorithm
            +Asn1Primitive(0u.toImplicitTag(), encryptedContent)
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as EncryptedContentInfo

        if (contentEncryptionAlgorithm != other.contentEncryptionAlgorithm) return false
        if (!encryptedContent.contentEquals(other.encryptedContent)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = contentEncryptionAlgorithm.hashCode()
        result = 31 * result + encryptedContent.contentHashCode()
        return result
    }


    companion object : Asn1Decodable<Asn1Sequence, EncryptedContentInfo> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): EncryptedContentInfo {
            val objectIdentifier = ObjectIdentifier.decodeFromTlv(src.nextChild() as Asn1Primitive)
            //TODO: make it variable, to support non-authenticated encryption algorithms
            if (objectIdentifier != KnownOIDs.authEnvelopedData) throw Asn1OidException(
                "Expected oid ${KnownOIDs.authEnvelopedData} but got $objectIdentifier",
                KnownOIDs.authEnvelopedData
            )
            return EncryptedContentInfo(
                src.nextChild() as Asn1Sequence,
                (src.nextChild() as Asn1Primitive).also {
                    if (it.tag != 0u.toImplicitTag()) throw Asn1TagMismatchException(
                        0u.toImplicitTag(),
                        it.tag
                    )
                }.content
            )
        }

    }

}

data class AuthEnvelopedData(
    /*version: fixed, skipped, no originator info*/
    /*fixed recipient info to ORI with a blursed oid*/
    val authEncryptedContentInfo: EncryptedContentInfo,
    /* no auth attrs for now*/
    val messageAuthenticationCode: ByteArray,
    /*no unauthedAttrs*/
) : Asn1Encodable<Asn1Sequence> {
    @Throws(Asn1Exception::class)
    override fun encodeToTlv(): Asn1Sequence {

        return Asn1.Sequence {
            +Asn1.Int(4)
            +blursedRecipientInfo
            +authEncryptedContentInfo
            +Asn1.OctetString(messageAuthenticationCode)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AuthEnvelopedData

        if (authEncryptedContentInfo != other.authEncryptedContentInfo) return false
        if (!messageAuthenticationCode.contentEquals(other.messageAuthenticationCode)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = authEncryptedContentInfo.hashCode()
        result = 31 * result + messageAuthenticationCode.contentHashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, AuthEnvelopedData> {
        private val blursedRecipientInfo = Asn1.SetOf {
            +Asn1.Tagged(4u) {
                Asn1.Sequence {
                    +KnownOIDs.otherRecipientInfoIds
                    +KnownOIDs.otherRecipientInfoIds
                }
            }
        }

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): AuthEnvelopedData {
            if ((src.nextChild() as Asn1Primitive).readInt() != 4) throw Asn1Exception("CMS Version Mismatch!")
            if (src.nextChild() != blursedRecipientInfo) throw Asn1StructuralException("Expected blursed recipient info")
            return AuthEnvelopedData(
                EncryptedContentInfo.decodeFromTlv(src.nextChild() as Asn1Sequence),
                (src.nextChild() as Asn1PrimitiveOctetString).content
            )

        }

    }
}