package at.asitplus.signum.indispensable.integrity

import at.asitplus.catching
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.digest

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

    suspend fun convertTo(format: SignatureInputFormat): SignatureInput {
        if (this.format == format) return this
        if (this.format != RAW_BYTES) throw IllegalStateException("Cannot convert signature input from ${this.format} to $format")
        format!! /* RAW_BYTES is null; this is for the compiler */
        return SignatureInput(sequenceOf(format.digest(this.data)), format)
    }

    /** Returns a [SignatureInput] in the same [format] but with only a single [data] element. */
    fun collapsed(): SignatureInput {
        val datas = data.toList()
        datas.singleOrNull()?.let { return SignatureInput(sequenceOf(it), format) }
        val size = datas.sumOf { it.size }
        val result = ByteArray(size)
        var offset = 0
        for (d in datas) {
            d.copyInto(result, offset, 0, d.size)
            offset += d.size
        }
        require(offset == result.size)
        return SignatureInput(sequenceOf(result), format)
    }

    constructor(data: ByteArray) : this(sequenceOf(data), RAW_BYTES)
    constructor(data: Sequence<ByteArray>): this(data, RAW_BYTES)
}
