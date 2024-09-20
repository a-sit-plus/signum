package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.asn1.encoding.encodeTo4Bytes

object JwsExtensions {

    /**
     * Prepend `this` with the size as four bytes
     */
    fun ByteArray.prependWith4BytesSize() = this.size.encodeTo4Bytes() + this

}

