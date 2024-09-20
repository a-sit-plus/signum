package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.asAsn1String
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

//TODO auto-sanitize and/or reduce
/**
 * ASN.! String class used as wrapper do discriminate between different ASN.1 string types
 */
@Serializable
sealed class Asn1String : Asn1Encodable<Asn1Primitive> {
    abstract val tag: ULong
    abstract val value: String

    /**
     * UTF8 STRING (verbatim String)
     */
    @Serializable
    @SerialName("UTF8String")
    class UTF8(override val value: String) : Asn1String() {
        override val tag = BERTags.UTF8_STRING.toULong()
    }

    /**
     * UNIVERSAL STRING (unchecked)
     */
    @Serializable
    @SerialName("UniversalString")
    class Universal(override val value: String) : Asn1String() {
        override val tag = BERTags.UNIVERSAL_STRING.toULong()
    }

    /**
     * VISIBLE STRING (no checks)
     */
    @Serializable
    @SerialName("VisibleString")
    class Visible(override val value: String) : Asn1String() {
        override val tag = BERTags.VISIBLE_STRING.toULong()
    }

    /**
     * IA5 STRING (no checks)
     */
    @Serializable
    @SerialName("IA5String")
    class IA5(override val value: String) : Asn1String() {
        override val tag = BERTags.IA5_STRING.toULong()
    }

    /**
     * TELETEX STRING (no checks)
     */
    @Serializable
    @SerialName("TeletexString")
    class Teletex(override val value: String) : Asn1String() {
        override val tag = BERTags.T61_STRING.toULong()
    }

    /**
     * BMP STRING (no checks)
     */
    @Serializable
    @SerialName("BMPString")
    class BMP(override val value: String) : Asn1String() {
        override val tag = BERTags.BMP_STRING.toULong()
    }

    /**
     * PRINTABLE STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    @Serializable
    @SerialName("PrintableString")

    class Printable @Throws(Asn1Exception::class) constructor(override val value: String) : Asn1String() {
        init {
            Regex("[a-zA-Z0-9 '()+,-./:=?]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        override val tag = BERTags.PRINTABLE_STRING.toULong()
    }

    /**
     * NUMERIC STRING (checked)
     * @throws Asn1Exception if illegal characters are provided
     */
    @Serializable
    @SerialName("NumericString")
    class Numeric @Throws(Asn1Exception::class) constructor(override val value: String) : Asn1String() {
        init {
            Regex("[0-9 ]*").matchEntire(value)
                ?: throw Asn1Exception("Input contains invalid chars: '$value'")
        }

        override val tag = BERTags.NUMERIC_STRING.toULong()
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
        override fun doDecode(src: Asn1Primitive): Asn1String = src.asAsn1String()
    }
}