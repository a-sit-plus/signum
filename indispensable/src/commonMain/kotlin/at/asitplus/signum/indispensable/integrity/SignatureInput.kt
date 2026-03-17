package at.asitplus.signum.indispensable.integrity

import at.asitplus.catching
import at.asitplus.signum.indispensable.digest.Digest

typealias SignatureInputFormat = Digest?
private fun Digest.digest(data: Sequence<ByteArray>): ByteArray = TODO()
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
}
