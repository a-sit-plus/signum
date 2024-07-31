package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.asn1.encodeTo4Bytes


//TODO a lot of this can now be streamlined thanks to our various helpers and ASN.1 Foo

object JwsExtensions {

    /**
     * ASN.1 encoding about encoding of integers:
     * Bits of first octet and bit 8 of the second octet
     * shall not be all ones; and shall not be all zeros
     */
    private fun ByteArray.toAsn1Integer() = if (this[0] < 0) byteArrayOf(0) + this else
        if (this[0] == 0x00.toByte() && this[1] > 0) drop(1).toByteArray() else this

    /**
     * Prepend `this` with the size as four bytes
     */
    fun ByteArray.prependWith4BytesSize() = this.size.encodeTo4Bytes() + this

}

