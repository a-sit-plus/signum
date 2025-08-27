package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.BERTags.BMP_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.GENERAL_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.GRAPHIC_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.IA5_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.NUMERIC_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.PRINTABLE_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.T61_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.UNIVERSAL_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.UNRESTRICTED_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.UTF8_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.VIDEOTEX_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.VISIBLE_STRING
import at.asitplus.signum.indispensable.asn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBmpString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToGeneralString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToGraphicString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToIa5String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToNumericString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToPrintableString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToTeletextString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUniversalString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUnrestrictedString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUtf8String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToVideotexString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToVisibleString


//TODO auto-sanitize and/or reduce
/**
 * ASN.! String class used as wrapper do discriminate between different ASN.1 string types
 */
sealed class Asn1String(
    open val rawValue: ByteArray
) : Asn1Encodable<Asn1Primitive> {
    abstract val tag: ULong
    val value: String by lazy { String.decodeFromAsn1ContentBytes(rawValue) }

    /**
     * UTF8 STRING (verbatim String)
     */
    class UTF8(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.UTF8_STRING.toULong()

        init {
            if (value.contains('\uFFFD')) throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * UNIVERSAL STRING (checked)
     */
    class Universal(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.UNIVERSAL_STRING.toULong()

        init {
            if (
                rawValue.size % 4 != 0 ||
                !(rawValue.indices step 4).all { i ->
                    val codePoint =
                        (rawValue[i].toInt() and 0xFF shl 24) or
                                (rawValue[i + 1].toInt() and 0xFF shl 16) or
                                (rawValue[i + 2].toInt() and 0xFF shl 8) or
                                (rawValue[i + 3].toInt() and 0xFF)
                    codePoint in 0x0000..0x10FFFF && codePoint !in 0xD800..0xDFFF
                }
            )
                throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * VISIBLE STRING (checked)
     */
    class Visible(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.VISIBLE_STRING.toULong()

        init {
            Regex("[\\x20-\\x7E]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * IA5 STRING (checked)
     */
    class IA5(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.IA5_STRING.toULong()

        init {
            Regex("[\\x00-\\x7E]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * TELETEX STRING (checked)
     */
    class Teletex(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.T61_STRING.toULong()

        init {
            Regex("[\\u0000-\\u00FF]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * BMP STRING (checked)
     */
    class BMP(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.BMP_STRING.toULong()

        init {
            if (
                rawValue.size % 2 != 0 ||
                !(rawValue.indices step 2).all { i ->
                    val unit = (rawValue[i].toInt() and 0xFF shl 8) or
                            (rawValue[i + 1].toInt() and 0xFF)
                    unit in 0x0000..0xD7FF || unit in 0xE000..0xFFFF
                }
            ) {
                throw Asn1Exception("Input contains invalid chars: '$value'")
            }
        }
    }

    /**
     * GENERAL STRING (checked)
     */
    class General(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.GENERAL_STRING.toULong()

        init {
            Regex("[\\x00-\\x7E]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * GRAPHIC STRING (checked)
     */
    class Graphic(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.GRAPHIC_STRING.toULong()

        init {
            Regex("[\\x20-\\x7E]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * CHARACTER/UNRESTRICTED STRING (no checks)
     */
    class Unrestricted(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.UNRESTRICTED_STRING.toULong()
    }

    /**
     * VIDEOTEX STRING (no checks)
     */
    class Videotex(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.VIDEOTEX_STRING.toULong()
    }

    /**
     * PRINTABLE STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class Printable @Throws(Asn1Exception::class) constructor(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.PRINTABLE_STRING.toULong()

        init {
            Regex("[a-zA-Z0-9 '()+,-./:=?]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * NUMERIC STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class Numeric @Throws(Asn1Exception::class) constructor(rawValue: ByteArray) : Asn1String(rawValue) {
        override val tag = BERTags.NUMERIC_STRING.toULong()

        init {
            Regex("[0-9 ]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    override fun encodeToTlv() = Asn1Primitive(tag, rawValue)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Asn1String

        if (tag != other.tag) return false
        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Primitive, Asn1String> {

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Primitive): Asn1String = runRethrowing {
            when (src.tag.tagValue) {
                UTF8_STRING.toULong() -> src.decodeToUtf8String()
                UNIVERSAL_STRING.toULong() -> src.decodeToUniversalString()
                IA5_STRING.toULong() -> src.decodeToIa5String()
                BMP_STRING.toULong() -> src.decodeToBmpString()
                T61_STRING.toULong() -> src.decodeToTeletextString()
                PRINTABLE_STRING.toULong() -> src.decodeToPrintableString()
                NUMERIC_STRING.toULong() -> src.decodeToNumericString()
                VISIBLE_STRING.toULong() -> src.decodeToVisibleString()
                GENERAL_STRING.toULong() -> src.decodeToGeneralString()
                GRAPHIC_STRING.toULong() -> src.decodeToGraphicString()
                UNRESTRICTED_STRING.toULong() -> src.decodeToUnrestrictedString()
                VIDEOTEX_STRING.toULong() -> src.decodeToVideotexString()
                else -> throw Asn1Exception("Not an Asn1String!")
            }
        }
    }
}