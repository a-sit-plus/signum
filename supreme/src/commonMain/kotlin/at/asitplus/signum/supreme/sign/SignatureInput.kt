package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.supreme.hash.digest
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

typealias SignatureInputFormat = Digest?
private val RAW_BYTES: SignatureInputFormat = null
class SignatureInput private constructor (
    val data: Sequence<ByteArray>,
    val format: SignatureInputFormat
){

    companion object {
        /** only use this if you know what you are doing */
        fun unsafeCreate(data: ByteArray, format: SignatureInputFormat): SignatureInput {
            if (format != null)
                require(data.size == format.outputLength.bytes.toInt())

            return SignatureInput(sequenceOf(data), format)
        }
    }

    fun convertTo(format: SignatureInputFormat) = catching {
        if (this.format == format) return@catching this
        if (this.format != RAW_BYTES) throw IllegalStateException("Cannot convert from ${this.format} to $format")
        format!! /* RAW_BYTES is null; this is for the compiler */
        SignatureInput(sequenceOf(format.digest(this.data)), format)
    }

    constructor(data: ByteArray) : this(sequenceOf(data), RAW_BYTES)
    constructor(data: Sequence<ByteArray>): this(data, RAW_BYTES)

    /**
     * Takes the leftmost bits of the byte array, and converts them to an unsigned `BigInteger`.
     *
     * (This matches the ECDSA spec.)
     */
    internal fun asBigInteger(length: BitLength): BigInteger {
        val target = length.bytes.toInt()
        val dataIt = data.iterator()
        var resultBytes = if(dataIt.hasNext()) dataIt.next() else byteArrayOf()
        while (resultBytes.size < target) {
            if (dataIt.hasNext()) resultBytes += dataIt.next().also { require(it.isNotEmpty()) }
            else break
        }
        if (resultBytes.size > target)
            resultBytes = resultBytes.copyOfRange(0, target)
        require(resultBytes.size <= target)

        return BigInteger.fromByteArray(resultBytes, Sign.POSITIVE).let {
            if ((resultBytes.size == target) && (length.bitSpacing != 0u))
                it.shr(length.bitSpacing.toInt())
            else
                it
        }
    }
}
