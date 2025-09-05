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


/**
 * ASN.1 String class used as wrapper do discriminate between different ASN.1 string types
 * By default, the string value is decoded using UTF-8. If a different charset or custom decoding
 * is needed, the [rawValue] property can be used directly.
 *
 * Constructor distinctions:
 *
 * 1. **Public constructors (String input)**
 *    - These constructors validate the input against the allowed character set for that
 *      specific ASN.1 string type (e.g., PrintableString, IA5String).
 *    - This ensures that strings created by library users are always valid.
 *
 * 2. **Internal/raw constructors (ByteArray input)**
 *    - These constructors don't performing validation.
 *    - Used internally for decoding ASN.1 strings to be able to accept illegal encodings.
 */
sealed class Asn1String(
    val rawValue: ByteArray,
    val isValidated: Boolean
) : Asn1Encodable<Asn1Primitive> {
    abstract val tag: ULong
    val value: String by lazy { String.decodeFromAsn1ContentBytes(rawValue) }

    /**
     * Returns whether this string is valid:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented
     */
    abstract val isValid: Boolean?


    /**
     * UTF8 STRING (verbatim String)
     * @throws Asn1Exception if illegal characters are provided
     */
    class UTF8 private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.UTF8_STRING.toULong()

        override val isValid: Boolean by lazy {
            !value.contains('\uFFFD')
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * UNIVERSAL STRING (unchecked)
     */
    class Universal private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.UNIVERSAL_STRING.toULong()

        override val isValid: Boolean? = null

        constructor(value: String) : this(value.encodeToByteArray(), false)

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * VISIBLE STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class Visible private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.VISIBLE_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\x20-\\x7E]*").matches(value)
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * IA5 STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class IA5 private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.IA5_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\x00-\\x7E]*").matches(value)
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * TELETEX STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class Teletex private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.T61_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\u0000-\\u00FF]*").matches(value)
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * BMP STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class BMP private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.BMP_STRING.toULong()

        override val isValid: Boolean by lazy {
            !(rawValue.size % 2 != 0 || !(rawValue.indices step 2).all { i ->
                val unit =
                    (rawValue[i].toInt() and 0xFF shl 8) or (rawValue[i + 1].toInt() and 0xFF)
                unit in 0x0000..0xD7FF || unit in 0xE000..0xFFFF
            })
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * GENERAL STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class General private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.GENERAL_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\x00-\\x7E]*").matches(value)
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * GRAPHIC STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class Graphic private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.GRAPHIC_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[\\x20-\\x7E]*").matches(value)
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * CHARACTER/UNRESTRICTED STRING (no checks)
     */
    class Unrestricted private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.UNRESTRICTED_STRING.toULong()

        override val isValid: Boolean? = null

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * VIDEOTEX STRING (no checks)
     */
    class Videotex private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.VIDEOTEX_STRING.toULong()

        override val isValid: Boolean? = null

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * PRINTABLE STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class Printable private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.PRINTABLE_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[a-zA-Z0-9 '()+,-./:=?]*").matches(value)
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
    }

    /**
     * NUMERIC STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    class Numeric private constructor(
        rawValue: ByteArray,
        isValidated: Boolean
    ) : Asn1String(rawValue, isValidated) {
        override val tag = BERTags.NUMERIC_STRING.toULong()

        override val isValid: Boolean by lazy {
            Regex("[0-9 ]*").matches(value)
        }

        @Throws(Asn1Exception::class)
        constructor(value: String) : this(value.encodeToByteArray(), true) {
            if (!isValid) throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        @PublishedApi
        internal constructor(rawValue: ByteArray) : this(rawValue, false)
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

        /**
         * Decodes an [Asn1Primitive] into a specific [Asn1String] subtype based on its tag.
         *
         * For cases where an implicit tag is required, see the helper extension methods
         * like [decodeToUtf8String], [decodeToPrintableString], etc., which allow specifying an optional tag override.
         *
         * @param src the ASN.1 primitive to decode
         * @return the corresponding [Asn1String] subtype
         * @throws Asn1Exception if decoding fails or the tag is unsupported
         */
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