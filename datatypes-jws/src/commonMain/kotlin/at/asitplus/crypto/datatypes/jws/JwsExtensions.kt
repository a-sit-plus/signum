package at.asitplus.crypto.datatypes.jws

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import at.asitplus.crypto.datatypes.asn1.padWithZeros
import at.asitplus.crypto.datatypes.asn1.stripLeadingSignByte

object JwsExtensions {

    private val ASN1_TAG_SEQUENCE = 0x30.toByte()
    private val ASN1_TAG_INTEGER = 0x02.toByte()

    /**
     * Extracts the plain R and S values of an ECDSA signature
     * if it is wrapped in an ASN.1 Sequence of two ASN.1 Integers
     * (e.g. when computed in Java)
     */
    fun ByteArray.extractSignatureValues(expectedLength: Int): ByteArray {
        if (this[0] != ASN1_TAG_SEQUENCE) return this
        val sequenceLen = this[1]
        if (size != (2 + sequenceLen)) return this
        val rTag = this[2]
        if (rTag != ASN1_TAG_INTEGER) return this
        val rLength = this[3]
        if (size < 4 + rLength) return this
        val rStartIndex = 4
        val rEndIndex = rStartIndex + rLength
        val sTag = this[rEndIndex]
        if (sTag != ASN1_TAG_INTEGER) return this
        val sLength = this[rEndIndex + 1]
        if (size != (6 + rLength + sLength)) return this
        val sStartIndex = rEndIndex + 2
        val sEndIndex = sStartIndex + sLength
        val rValue = sliceArray(rStartIndex until rEndIndex)
        val sValue = sliceArray(sStartIndex until sEndIndex)
        val rValueRaw = rValue.stripLeadingSignByte().padWithZeros(expectedLength)
        val sValueRaw = sValue.stripLeadingSignByte().padWithZeros(expectedLength)
        return rValueRaw + sValueRaw
    }

    /**
     * JWS spec concatenates the R and S values,
     * but JCA needs an ASN.1 structure (SEQUENCE of two INTEGER) around it
     */
    fun ByteArray.convertToAsn1Signature(len: Int): ByteArray = if (size == len * 2) {
        val rValue = sliceArray(0 until len).toAsn1Integer()
        val sValue = sliceArray(len until len * 2).toAsn1Integer()
        val rAsn1Int = byteArrayOf(ASN1_TAG_INTEGER) + rValue.size.toByte() + rValue
        val sAsn1Int = byteArrayOf(ASN1_TAG_INTEGER) + sValue.size.toByte() + sValue
        byteArrayOf(ASN1_TAG_SEQUENCE) + (rAsn1Int.size + sAsn1Int.size).toByte() + rAsn1Int + sAsn1Int
    } else {
        this
    }

    /**
     * ASN.1 encoding about encoding of integers:
     * Bits of first octet and bit 8 of the second octet
     * shall not be all ones; and shall not be all zeros
     */
    private fun ByteArray.toAsn1Integer() = if (this[0] < 0) byteArrayOf(0) + this else
        if (this[0] == 0x00.toByte() && this[1] > 0) drop(1).toByteArray() else this

    /**
     * Encode the length of (as four bytes) plus the value itself
     */
    fun ByteArray?.encodeWithLength() = (this?.size ?: 0).encodeToByteArray() + (this ?: byteArrayOf())

}

