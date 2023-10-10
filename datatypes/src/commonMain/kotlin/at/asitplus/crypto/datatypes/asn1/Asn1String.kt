package at.asitplus.crypto.datatypes.asn1

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

//TODO auto-sanitize and/or reduce
@Serializable
sealed class Asn1String : Asn1Encodable<Asn1Primitive> {
    abstract val tag: UByte
    abstract val value: String

    @Serializable
    @SerialName("UTF8String")
    class UTF8(override val value: String) : Asn1String() {
        override val tag = BERTags.UTF8_STRING
    }

    @Serializable
    @SerialName("UniversalString")
    class Universal(override val value: String) : Asn1String() {
        override val tag = BERTags.UNIVERSAL_STRING
    }

    @Serializable
    @SerialName("VisibleString")
    class Visible(override val value: String) : Asn1String() {
        override val tag = BERTags.VISIBLE_STRING
    }

    @Serializable
    @SerialName("IA5String")
    class IA5(override val value: String) : Asn1String() {
        override val tag = BERTags.IA5_STRING
    }

    @Serializable
    @SerialName("TeletexString")
    class Teletex(override val value: String) : Asn1String() {
        override val tag = BERTags.T61_STRING
    }

    @Serializable
    @SerialName("BMPString")
    class BMP(override val value: String) : Asn1String() {
        override val tag = BERTags.BMP_STRING
    }

    @Serializable
    @SerialName("PrintableString")
    class Printable(override val value: String) : Asn1String() {
        init {
            Regex("[a-zA-Z0-9 '()+,-./:=?]*").matchEntire(value)
                ?: throw IllegalArgumentException("Input contains invalid chars: '$value'")
        }

        override val tag = BERTags.PRINTABLE_STRING
    }

    @Serializable
    @SerialName("NumericString")
    class Numeric(override val value: String) : Asn1String() {
        init {
            Regex("[0-9 ]*").matchEntire(value)
                ?: throw IllegalArgumentException("Input contains invalid chars: '$value'")
        }

        override val tag = BERTags.NUMERIC_STRING
    }

    override fun encodeToTlv() = Asn1Primitive(tag, value.encodeToByteArray())

    companion object : Asn1Decodable<Asn1Primitive, Asn1String> {
        override fun decodeFromTlv(src: Asn1Primitive): Asn1String = src.readString()
    }
}