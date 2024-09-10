package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching

//Based on https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/asn1/BERTags.java
object BERTags {
    // 0x00: Reserved for use by the encoding rules
    const val BOOLEAN: UByte = 0x01u
    const val INTEGER: UByte = 0x02u
    const val BIT_STRING: UByte = 0x03u
    const val OCTET_STRING: UByte = 0x04u
    const val ASN1_NULL: UByte = 0x05u
    const val OBJECT_IDENTIFIER: UByte = 0x06u
    const val OBJECT_DESCRIPTOR: UByte = 0x07u
    const val EXTERNAL: UByte = 0x08u
    const val REAL: UByte = 0x09u
    const val ENUMERATED: UByte = 0x0au // decimal 10
    const val EMBEDDED_PDV: UByte = 0x0bu // decimal 11
    const val UTF8_STRING: UByte = 0x0cu // decimal 12
    const val RELATIVE_OID: UByte = 0x0du // decimal 13
    const val TIME: UByte = 0x0eu

    // 0x0f: Reserved for future editions of this Recommendation | International Standard
    const val SEQUENCE: UByte = 0x10u // decimal 16
    const val SEQUENCE_OF: UByte = 0x10u // for completeness - used to model a SEQUENCE of the same type.
    const val SET: UByte = 0x11u // decimal 17
    const val SET_OF: UByte = 0x11u // for completeness - used to model a SET of the same type.
    const val NUMERIC_STRING: UByte = 0x12u // decimal 18
    const val PRINTABLE_STRING: UByte = 0x13u // decimal 19
    const val T61_STRING: UByte = 0x14u // decimal 20
    const val VIDEOTEX_STRING: UByte = 0x15u // decimal 21
    const val IA5_STRING: UByte = 0x16u // decimal 22
    const val UTC_TIME: UByte = 0x17u // decimal 23
    const val GENERALIZED_TIME: UByte = 0x18u // decimal 24
    const val GRAPHIC_STRING: UByte = 0x19u // decimal 25
    const val VISIBLE_STRING: UByte = 0x1au // decimal 26
    const val GENERAL_STRING: UByte = 0x1bu // decimal 27
    const val UNIVERSAL_STRING: UByte = 0x1cu // decimal 28
    const val UNRESTRICTED_STRING: UByte = 0x1du // decimal 29
    const val BMP_STRING: UByte = 0x1eu // decimal 30
    const val DATE: UByte = 0x1fu
    const val TIME_OF_DAY: UByte = 0x20u
    const val DATE_TIME: UByte = 0x21u
    const val DURATION: UByte = 0x22u
    const val OBJECT_IDENTIFIER_IRI: UByte = 0x23u
    const val RELATIVE_OID_IRI: UByte = 0x24u

    // 0x25..: Reserved for addenda to this Recommendation | International Standard
    const val CONSTRUCTED: UByte = 0x20u // decimal 32
    const val UNIVERSAL: UByte = 0x00u // decimal 32
    const val APPLICATION: UByte = 0x40u // decimal 64
    const val CONTEXT_SPECIFIC: UByte = 0x80u // decimal 128
    const val PRIVATE: UByte = 0xC0u // decimal 192
    const val FLAGS: UByte = 0xE0u

}

/**
 * Convenience helper to easily construct implicitly tagged elements. Can be CONSTRUCTED or PRIMITIVE
 * @param constructed whether to set the constructed bit
 */
fun ULong.toImplicitTag(constructed: Boolean = false) =
    TLV.Tag(this, constructed = constructed, tagClass = TagClass.CONTEXT_SPECIFIC)

fun UByte.isConstructed() = this and BERTags.CONSTRUCTED != 0.toUByte()


enum class TagClass(val byteValue:UByte) {
    UNIVERSAL(0u),
    APPLICATION(1u),
    CONTEXT_SPECIFIC(2u),
    PRIVATE(3u);
    companion object {
        fun fromByte(byteValue: Byte): KmmResult<TagClass> =
            catching { entries.first { it.byteValue == ((byteValue byteMask 0xC0).toUInt().toInt() ushr 6).toUByte()  } }
    }

}