@file:Suppress("unused")

package at.asitplus.signum.indispensable.asn1

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.memDumpView as awesn1MemDumpView
import at.asitplus.awesn1.readOid as awesn1ReadOid
import at.asitplus.awesn1.toBitSet as awesn1ToBitSet
import at.asitplus.awesn1.toBitStringView as awesn1ToBitStringView
import kotlinx.serialization.KSerializer

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1BitString.",
    ReplaceWith("at.asitplus.awesn1.Asn1BitString")
)
typealias Asn1BitString = at.asitplus.awesn1.Asn1BitString

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Element.",
    ReplaceWith("at.asitplus.awesn1.Asn1Element")
)
typealias Asn1Element = at.asitplus.awesn1.Asn1Element

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Structure.",
    ReplaceWith("at.asitplus.awesn1.Asn1Structure")
)
typealias Asn1Structure = at.asitplus.awesn1.Asn1Structure

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Primitive.",
    ReplaceWith("at.asitplus.awesn1.Asn1Primitive")
)
typealias Asn1Primitive = at.asitplus.awesn1.Asn1Primitive

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1ExplicitlyTagged.",
    ReplaceWith("at.asitplus.awesn1.Asn1ExplicitlyTagged")
)
typealias Asn1ExplicitlyTagged = at.asitplus.awesn1.Asn1ExplicitlyTagged

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Sequence.",
    ReplaceWith("at.asitplus.awesn1.Asn1Sequence")
)
typealias Asn1Sequence = at.asitplus.awesn1.Asn1Sequence

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1CustomStructure.",
    ReplaceWith("at.asitplus.awesn1.Asn1CustomStructure")
)
typealias Asn1CustomStructure = at.asitplus.awesn1.Asn1CustomStructure

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1EncapsulatingOctetString.",
    ReplaceWith("at.asitplus.awesn1.Asn1EncapsulatingOctetString")
)
typealias Asn1EncapsulatingOctetString = at.asitplus.awesn1.Asn1EncapsulatingOctetString

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1PrimitiveOctetString.",
    ReplaceWith("at.asitplus.awesn1.Asn1PrimitiveOctetString")
)
typealias Asn1PrimitiveOctetString = at.asitplus.awesn1.Asn1PrimitiveOctetString

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Set.",
    ReplaceWith("at.asitplus.awesn1.Asn1Set")
)
typealias Asn1Set = at.asitplus.awesn1.Asn1Set

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1SetOf.",
    ReplaceWith("at.asitplus.awesn1.Asn1SetOf")
)
typealias Asn1SetOf = at.asitplus.awesn1.Asn1SetOf

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Encodable.",
    ReplaceWith("at.asitplus.awesn1.Asn1Encodable")
)
typealias Asn1Encodable<A> = at.asitplus.awesn1.Asn1Encodable<A>

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Decodable.",
    ReplaceWith("at.asitplus.awesn1.Asn1Decodable")
)
typealias Asn1Decodable<A, T> = at.asitplus.awesn1.Asn1Decodable<A, T>

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Exception.",
    ReplaceWith("at.asitplus.awesn1.Asn1Exception")
)
typealias Asn1Exception = at.asitplus.awesn1.Asn1Exception

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1TagMismatchException.",
    ReplaceWith("at.asitplus.awesn1.Asn1TagMismatchException")
)
typealias Asn1TagMismatchException = at.asitplus.awesn1.Asn1TagMismatchException

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1StructuralException.",
    ReplaceWith("at.asitplus.awesn1.Asn1StructuralException")
)
typealias Asn1StructuralException = at.asitplus.awesn1.Asn1StructuralException

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1OidException.",
    ReplaceWith("at.asitplus.awesn1.Asn1OidException")
)
typealias Asn1OidException = at.asitplus.awesn1.Asn1OidException

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Integer.",
    ReplaceWith("at.asitplus.awesn1.Asn1Integer")
)
typealias Asn1Integer = at.asitplus.awesn1.Asn1Integer

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Real.",
    ReplaceWith("at.asitplus.awesn1.Asn1Real")
)
typealias Asn1Real = at.asitplus.awesn1.Asn1Real

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.",
    ReplaceWith("Asn1String", "at.asitplus.awesn1.Asn1String")
)
typealias Asn1String = at.asitplus.awesn1.Asn1String

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Time.",
    ReplaceWith("Asn1Time", "at.asitplus.awesn1.Asn1Time")
)
typealias Asn1Time = at.asitplus.awesn1.Asn1Time

@Deprecated(
    "Moved to at.asitplus.awesn1.BitSet.",
    ReplaceWith("at.asitplus.awesn1.BitSet")
)
typealias BitSet = at.asitplus.awesn1.BitSet

@Deprecated(
    "Moved to at.asitplus.awesn1.ObjectIdentifier.",
    ReplaceWith("at.asitplus.awesn1.ObjectIdentifier")
)
typealias ObjectIdentifier = at.asitplus.awesn1.ObjectIdentifier

@Deprecated(
    "Moved to at.asitplus.awesn1.Identifiable.",
    ReplaceWith("at.asitplus.awesn1.Identifiable")
)
typealias Identifiable = at.asitplus.awesn1.Identifiable

@Deprecated(
    "Moved to at.asitplus.awesn1.TagClass.",
    ReplaceWith("at.asitplus.awesn1.TagClass")
)
typealias TagClass = at.asitplus.awesn1.TagClass

@Deprecated(
    "Moved to at.asitplus.awesn1.TagProperty.",
    ReplaceWith("at.asitplus.awesn1.TagProperty")
)
typealias TagProperty = at.asitplus.awesn1.TagProperty

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Null.",
    ReplaceWith("at.asitplus.awesn1.Asn1Null")
)
val Asn1Null: Asn1Primitive
    get() = at.asitplus.awesn1.Asn1Null

@Deprecated(
    "Moved to at.asitplus.awesn1.BERTags.",
    ReplaceWith("at.asitplus.awesn1.BERTags")
)
object BERTags {
    const val BOOLEAN: UByte = at.asitplus.awesn1.BERTags.BOOLEAN
    const val INTEGER: UByte = at.asitplus.awesn1.BERTags.INTEGER
    const val BIT_STRING: UByte = at.asitplus.awesn1.BERTags.BIT_STRING
    const val OCTET_STRING: UByte = at.asitplus.awesn1.BERTags.OCTET_STRING
    const val ASN1_NULL: UByte = at.asitplus.awesn1.BERTags.ASN1_NULL
    const val OBJECT_IDENTIFIER: UByte = at.asitplus.awesn1.BERTags.OBJECT_IDENTIFIER
    const val OBJECT_DESCRIPTOR: UByte = at.asitplus.awesn1.BERTags.OBJECT_DESCRIPTOR
    const val EXTERNAL: UByte = at.asitplus.awesn1.BERTags.EXTERNAL
    const val REAL: UByte = at.asitplus.awesn1.BERTags.REAL
    const val ENUMERATED: UByte = at.asitplus.awesn1.BERTags.ENUMERATED
    const val EMBEDDED_PDV: UByte = at.asitplus.awesn1.BERTags.EMBEDDED_PDV
    const val UTF8_STRING: UByte = at.asitplus.awesn1.BERTags.UTF8_STRING
    const val RELATIVE_OID: UByte = at.asitplus.awesn1.BERTags.RELATIVE_OID
    const val TIME: UByte = at.asitplus.awesn1.BERTags.TIME
    const val SEQUENCE: UByte = at.asitplus.awesn1.BERTags.SEQUENCE
    const val SEQUENCE_OF: UByte = at.asitplus.awesn1.BERTags.SEQUENCE_OF
    const val SET: UByte = at.asitplus.awesn1.BERTags.SET
    const val SET_OF: UByte = at.asitplus.awesn1.BERTags.SET_OF
    const val NUMERIC_STRING: UByte = at.asitplus.awesn1.BERTags.NUMERIC_STRING
    const val PRINTABLE_STRING: UByte = at.asitplus.awesn1.BERTags.PRINTABLE_STRING
    const val T61_STRING: UByte = at.asitplus.awesn1.BERTags.T61_STRING
    const val VIDEOTEX_STRING: UByte = at.asitplus.awesn1.BERTags.VIDEOTEX_STRING
    const val IA5_STRING: UByte = at.asitplus.awesn1.BERTags.IA5_STRING
    const val UTC_TIME: UByte = at.asitplus.awesn1.BERTags.UTC_TIME
    const val GENERALIZED_TIME: UByte = at.asitplus.awesn1.BERTags.GENERALIZED_TIME
    const val GRAPHIC_STRING: UByte = at.asitplus.awesn1.BERTags.GRAPHIC_STRING
    const val VISIBLE_STRING: UByte = at.asitplus.awesn1.BERTags.VISIBLE_STRING
    const val GENERAL_STRING: UByte = at.asitplus.awesn1.BERTags.GENERAL_STRING
    const val UNIVERSAL_STRING: UByte = at.asitplus.awesn1.BERTags.UNIVERSAL_STRING
    const val UNRESTRICTED_STRING: UByte = at.asitplus.awesn1.BERTags.UNRESTRICTED_STRING
    const val BMP_STRING: UByte = at.asitplus.awesn1.BERTags.BMP_STRING
    const val DATE: UByte = at.asitplus.awesn1.BERTags.DATE
    const val TIME_OF_DAY: UByte = at.asitplus.awesn1.BERTags.TIME_OF_DAY
    const val DATE_TIME: UByte = at.asitplus.awesn1.BERTags.DATE_TIME
    const val DURATION: UByte = at.asitplus.awesn1.BERTags.DURATION
    const val OBJECT_IDENTIFIER_IRI: UByte = at.asitplus.awesn1.BERTags.OBJECT_IDENTIFIER_IRI
    const val RELATIVE_OID_IRI: UByte = at.asitplus.awesn1.BERTags.RELATIVE_OID_IRI
    const val CONSTRUCTED: UByte = at.asitplus.awesn1.BERTags.CONSTRUCTED
    const val UNIVERSAL: UByte = at.asitplus.awesn1.BERTags.UNIVERSAL
    const val APPLICATION: UByte = at.asitplus.awesn1.BERTags.APPLICATION
    const val CONTEXT_SPECIFIC: UByte = at.asitplus.awesn1.BERTags.CONTEXT_SPECIFIC
    const val PRIVATE: UByte = at.asitplus.awesn1.BERTags.PRIVATE
    const val FLAGS: UByte = at.asitplus.awesn1.BERTags.FLAGS
}

@Deprecated(
    "Moved to at.asitplus.awesn1.CONSTRUCTED.",
    ReplaceWith("at.asitplus.awesn1.CONSTRUCTED")
)
val CONSTRUCTED: TagProperty
    get() = at.asitplus.awesn1.CONSTRUCTED

@Deprecated(
    "Moved to at.asitplus.awesn1.KnownOIDs.",
    ReplaceWith("at.asitplus.awesn1.KnownOIDs")
)
object KnownOIDs : MutableMap<ObjectIdentifier, String> by at.asitplus.awesn1.KnownOIDs

@Deprecated(
    "Moved to at.asitplus.awesn1.ObjectIdentifierStringSerializer.",
    ReplaceWith("at.asitplus.awesn1.ObjectIdentifierStringSerializer")
)
object ObjectIdentifierStringSerializer : KSerializer<ObjectIdentifier> by at.asitplus.awesn1.ObjectIdentifierStringSerializer

@Deprecated(
    "Moved to at.asitplus.awesn1.BitSetSerializer.",
    ReplaceWith("at.asitplus.awesn1.BitSetSerializer")
)
object BitSetSerializer : KSerializer<BitSet> by at.asitplus.awesn1.BitSetSerializer

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1IntegerStringSerializer.",
    ReplaceWith("at.asitplus.awesn1.Asn1IntegerStringSerializer")
)
object Asn1IntegerSerializer : KSerializer<Asn1Integer> by at.asitplus.awesn1.Asn1IntegerStringSerializer

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1RealStringSerializer.",
    ReplaceWith("at.asitplus.awesn1.Asn1RealStringSerializer")
)
object Asn1RealSerializer : KSerializer<Asn1Real> by at.asitplus.awesn1.Asn1RealStringSerializer

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Integer(number).",
    ReplaceWith("at.asitplus.awesn1.Asn1Integer(number)")
)
fun Asn1Integer(number: Int): Asn1Integer = at.asitplus.awesn1.Asn1Integer(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Integer(number).",
    ReplaceWith("at.asitplus.awesn1.Asn1Integer(number)")
)
fun Asn1Integer(number: Long): Asn1Integer = at.asitplus.awesn1.Asn1Integer(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Integer(number).",
    ReplaceWith("at.asitplus.awesn1.Asn1Integer(number)")
)
fun Asn1Integer(number: UInt): Asn1Integer = at.asitplus.awesn1.Asn1Integer(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1Integer(number).",
    ReplaceWith("at.asitplus.awesn1.Asn1Integer(number)")
)
fun Asn1Integer(number: ULong): Asn1Integer = at.asitplus.awesn1.Asn1Integer(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.toBitSet().",
    ReplaceWith("at.asitplus.awesn1.toBitSet(this)")
)
fun ByteArray.toBitSet(): BitSet = awesn1ToBitSet()

@Deprecated(
    "Moved to at.asitplus.awesn1.toBitStringView().",
    ReplaceWith("at.asitplus.awesn1.toBitStringView(this)")
)
fun ByteArray.toBitString(): String = awesn1ToBitStringView()

@Deprecated(
    "Moved to at.asitplus.awesn1.BitSet.Companion.fromString().",
    ReplaceWith("at.asitplus.awesn1.BitSet.fromString(stringRepresentation)")
)
fun at.asitplus.awesn1.BitSet.Companion.fromBitString(stringRepresentation: String): BitSet =
    at.asitplus.awesn1.BitSet.fromString(stringRepresentation)

@Deprecated(
    "Moved to at.asitplus.awesn1.BitSet.toBitStringView().",
    ReplaceWith("at.asitplus.awesn1.BitSet.toBitStringView()")
)
fun BitSet.toBitString(): String = toBitStringView()

@Deprecated(
    "Moved to at.asitplus.awesn1.memDumpView().",
    ReplaceWith("at.asitplus.awesn1.memDumpView(this)")
)
fun ByteArray.memDump(): String = awesn1MemDumpView()

@Deprecated(
    "Moved to at.asitplus.awesn1.BitSet.memDumpView().",
    ReplaceWith("at.asitplus.awesn1.BitSet.memDumpView()")
)
fun BitSet.memDump(): String = memDumpView()

@Deprecated(
    "Moved to at.asitplus.awesn1.readOid().",
    ReplaceWith("at.asitplus.awesn1.readOid(this)")
)
fun Asn1Primitive.readOid(): ObjectIdentifier = awesn1ReadOid()

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.UTF8(value).",
    ReplaceWith("Asn1String.UTF8(value)", "at.asitplus.awesn1.Asn1String")
)
fun UTF8(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.UTF8(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.Universal(value).",
    ReplaceWith("Asn1String.Universal(value)", "at.asitplus.awesn1.Asn1String")
)
fun Universal(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.Universal(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.Visible(value).",
    ReplaceWith("Asn1String.Visible(value)", "at.asitplus.awesn1.Asn1String")
)
fun Visible(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.Visible(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.IA5(value).",
    ReplaceWith("Asn1String.IA5(value)", "at.asitplus.awesn1.Asn1String")
)
fun IA5(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.IA5(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.Teletex(value).",
    ReplaceWith("Asn1String.Teletex(value)", "at.asitplus.awesn1.Asn1String")
)
fun Teletex(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.Teletex(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.BMP(value).",
    ReplaceWith("Asn1String.BMP(value)", "at.asitplus.awesn1.Asn1String")
)
fun BMP(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.BMP(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.General(value).",
    ReplaceWith("Asn1String.General(value)", "at.asitplus.awesn1.Asn1String")
)
fun General(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.General(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.Graphic(value).",
    ReplaceWith("Asn1String.Graphic(value)", "at.asitplus.awesn1.Asn1String")
)
fun Graphic(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.Graphic(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.Unrestricted(value).",
    ReplaceWith("Asn1String.Unrestricted(value)", "at.asitplus.awesn1.Asn1String")
)
fun Unrestricted(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.Unrestricted(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.Videotex(value).",
    ReplaceWith("Asn1String.Videotex(value)", "at.asitplus.awesn1.Asn1String")
)
fun Videotex(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.Videotex(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.Printable(value).",
    ReplaceWith("Asn1String.Printable(value)", "at.asitplus.awesn1.Asn1String")
)
fun Printable(value: String): at.asitplus.awesn1.Asn1String = at.asitplus.awesn1.Asn1String.Printable(value)

@Deprecated(
    "Moved to at.asitplus.awesn1.Asn1String.Numeric(value).",
    ReplaceWith("Asn1String.Numeric(value)", "at.asitplus.awesn1.Asn1String")
)
fun Numeric(value: String): Asn1String = at.asitplus.awesn1.Asn1String.Numeric(value)
