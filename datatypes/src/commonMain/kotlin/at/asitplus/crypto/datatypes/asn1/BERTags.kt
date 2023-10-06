package at.asitplus.crypto.datatypes.asn1

//Basedon https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/asn1/BERTags.java
object BERTags {
        // 0x00: Reserved for use by the encoding rules
        const val BOOLEAN = 0x01
        const val INTEGER = 0x02
        const val BIT_STRING = 0x03
        const val OCTET_STRING = 0x04
        const val NULL = 0x05
        const val OBJECT_IDENTIFIER = 0x06
        const val OBJECT_DESCRIPTOR = 0x07
        const val EXTERNAL = 0x08
        const val REAL = 0x09
        const val ENUMERATED = 0x0a // decimal 10
        const val EMBEDDED_PDV = 0x0b // decimal 11
        const val UTF8_STRING = 0x0c // decimal 12
        const val RELATIVE_OID = 0x0d // decimal 13
        const val TIME = 0x0e

        // 0x0f: Reserved for future editions of this Recommendation | International Standard
        const val SEQUENCE = 0x10 // decimal 16
        const val SEQUENCE_OF = 0x10 // for completeness - used to model a SEQUENCE of the same type.
        const val SET = 0x11 // decimal 17
        const val SET_OF = 0x11 // for completeness - used to model a SET of the same type.
        const val NUMERIC_STRING = 0x12 // decimal 18
        const val PRINTABLE_STRING = 0x13 // decimal 19
        const val T61_STRING = 0x14 // decimal 20
        const val VIDEOTEX_STRING = 0x15 // decimal 21
        const val IA5_STRING = 0x16 // decimal 22
        const val UTC_TIME = 0x17 // decimal 23
        const val GENERALIZED_TIME = 0x18 // decimal 24
        const val GRAPHIC_STRING = 0x19 // decimal 25
        const val VISIBLE_STRING = 0x1a // decimal 26
        const val GENERAL_STRING = 0x1b // decimal 27
        const val UNIVERSAL_STRING = 0x1c // decimal 28
        const val UNRESTRICTED_STRING = 0x1d // decimal 29
        const val BMP_STRING = 0x1e // decimal 30
        const val DATE = 0x1f
        const val TIME_OF_DAY = 0x20
        const val DATE_TIME = 0x21
        const val DURATION = 0x22
        const val OBJECT_IDENTIFIER_IRI = 0x23
        const val RELATIVE_OID_IRI = 0x24

        // 0x25..: Reserved for addenda to this Recommendation | International Standard
        const val CONSTRUCTED = 0x20 // decimal 32
        const val UNIVERSAL = 0x00 // decimal 32
        const val APPLICATION = 0x40 // decimal 64
        const val TAGGED = 0x80 // decimal 128 - maybe should deprecate this.
        const val CONTEXT_SPECIFIC = 0x80 // decimal 128
        const val PRIVATE = 0xC0 // decimal 192
        const val FLAGS = 0xE0

}

object DERTags {
    const val DER_SEQUENCE = BERTags.CONSTRUCTED or BERTags.SEQUENCE
    const val DER_SET = BERTags.CONSTRUCTED or BERTags.SET
}