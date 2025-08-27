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
import at.asitplus.signum.indispensable.asn1.encoding.decodeToIa5String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToNumericString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToPrintableString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToTeletextString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUniversalString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToUtf8String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToVisibleString


//TODO auto-sanitize and/or reduce
/**
 * ASN.! String class used as wrapper do discriminate between different ASN.1 string types
 */
sealed class Asn1String : Asn1Encodable<Asn1Primitive> {
    abstract val tag: ULong
    abstract val rawValue: ByteArray
    abstract val value: String

    /**
     * UTF8 STRING (verbatim String)
     */
    class UTF8(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        override val tag = BERTags.UTF8_STRING.toULong()

        init {
            if (value.contains('\uFFFD')) throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * UNIVERSAL STRING (unchecked)
     */
    class Universal(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        override val tag = BERTags.UNIVERSAL_STRING.toULong()
    }

    /**
     * VISIBLE STRING (no checks)
     */
    class Visible(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        init {
            Regex("[\\x20-\\x7E]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
        override val tag = BERTags.VISIBLE_STRING.toULong()
    }

    /**
     * IA5 STRING (no checks)
     */
    class IA5(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        init {
            Regex("[\\x00-\\x7E]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
        override val tag = BERTags.IA5_STRING.toULong()
    }

    /**
     * TELETEX STRING (no checks)
     */
    class Teletex(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        override val tag = BERTags.T61_STRING.toULong()
    }

    /**
     * BMP STRING (no checks)
     */
    class BMP(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        override val tag = BERTags.BMP_STRING.toULong()
    }

    /**
     * GENERAL STRING (no checks)
     */
    class General(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        override val tag = BERTags.GENERAL_STRING.toULong()
        init {
            Regex("[\\x00-\\x7E]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    /**
     * GRAPHIC STRING (no checks)
     */
    class Graphic(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        init {
            Regex("[\\x20-\\x7E]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
        override val tag = BERTags.GRAPHIC_STRING.toULong()
    }

    /**
     * CHARACTER/UNRESTRICTED STRING (no checks)
     */
    class Unrestricted(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        override val tag = BERTags.UNRESTRICTED_STRING.toULong()
    }

    /**
     * VIDEOTEX STRING (no checks)
     */
    class Videotex(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        override val tag = BERTags.VIDEOTEX_STRING.toULong()
    }

    /**
     * PRINTABLE STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class Printable @Throws(Asn1Exception::class) constructor(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
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
    class Numeric @Throws(Asn1Exception::class) constructor(override val rawValue: ByteArray) : Asn1String() {
        override val value = String.decodeFromAsn1ContentBytes(rawValue)
        override val tag = BERTags.NUMERIC_STRING.toULong()

        init {
            Regex("[0-9 ]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }
    }

    override fun encodeToTlv() = Asn1Primitive(tag, value.encodeToByteArray())
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
                GENERAL_STRING.toULong() -> src.decodeToVisibleString()
                GRAPHIC_STRING.toULong() -> src.decodeToVisibleString()
                UNRESTRICTED_STRING.toULong() -> src.decodeToVisibleString()
                VIDEOTEX_STRING.toULong() -> src.decodeToVisibleString()
                else -> throw Asn1Exception("Not an Asn1String!")
            }
        }
    }
}