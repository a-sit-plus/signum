@file:Suppress("unused", "NOTHING_TO_INLINE")

package at.asitplus.signum.indispensable.asn1.encoding

import at.asitplus.signum.indispensable.asn1.Asn1BitString
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Real
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.encoding.asAsn1BitString as awesn1AsAsn1BitString
import at.asitplus.awesn1.encoding.asAsn1String as awesn1AsAsn1String
import at.asitplus.awesn1.encoding.decode as awesn1Decode
import at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes as awesn1DecodeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.decodeGeneralizedTimeFromAsn1ContentBytes as awesn1DecodeGeneralizedTimeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.decodeOrNull as awesn1DecodeOrNull
import at.asitplus.awesn1.encoding.decodeToAsn1Integer as awesn1DecodeToAsn1Integer
import at.asitplus.awesn1.encoding.decodeToAsn1IntegerOrNull as awesn1DecodeToAsn1IntegerOrNull
import at.asitplus.awesn1.encoding.decodeToAsn1Real as awesn1DecodeToAsn1Real
import at.asitplus.awesn1.encoding.decodeToAsn1RealOrNull as awesn1DecodeToAsn1RealOrNull
import at.asitplus.awesn1.encoding.decodeToBmpString as awesn1DecodeToBmpString
import at.asitplus.awesn1.encoding.decodeToBoolean as awesn1DecodeToBoolean
import at.asitplus.awesn1.encoding.decodeToBooleanOrNull as awesn1DecodeToBooleanOrNull
import at.asitplus.awesn1.encoding.decodeToDouble as awesn1DecodeToDouble
import at.asitplus.awesn1.encoding.decodeToDoubleOrNull as awesn1DecodeToDoubleOrNull
import at.asitplus.awesn1.encoding.decodeToEnum as awesn1DecodeToEnum
import at.asitplus.awesn1.encoding.decodeToEnumOrdinal as awesn1DecodeToEnumOrdinal
import at.asitplus.awesn1.encoding.decodeToEnumOrdinalOrNull as awesn1DecodeToEnumOrdinalOrNull
import at.asitplus.awesn1.encoding.decodeToEnumOrNull as awesn1DecodeToEnumOrNull
import at.asitplus.awesn1.encoding.decodeToFloat as awesn1DecodeToFloat
import at.asitplus.awesn1.encoding.decodeToFloatOrNull as awesn1DecodeToFloatOrNull
import at.asitplus.awesn1.encoding.decodeToGeneralString as awesn1DecodeToGeneralString
import at.asitplus.awesn1.encoding.decodeToGraphicString as awesn1DecodeToGraphicString
import at.asitplus.awesn1.encoding.decodeToIa5String as awesn1DecodeToIa5String
import at.asitplus.awesn1.encoding.decodeToInstant as awesn1DecodeToInstant
import at.asitplus.awesn1.encoding.decodeToInstantOrNull as awesn1DecodeToInstantOrNull
import at.asitplus.awesn1.encoding.decodeToInt as awesn1DecodeToInt
import at.asitplus.awesn1.encoding.decodeToIntOrNull as awesn1DecodeToIntOrNull
import at.asitplus.awesn1.encoding.decodeToLong as awesn1DecodeToLong
import at.asitplus.awesn1.encoding.decodeToLongOrNull as awesn1DecodeToLongOrNull
import at.asitplus.awesn1.encoding.decodeToNumericString as awesn1DecodeToNumericString
import at.asitplus.awesn1.encoding.decodeToPrintableString as awesn1DecodeToPrintableString
import at.asitplus.awesn1.encoding.decodeToString as awesn1DecodeToString
import at.asitplus.awesn1.encoding.decodeToStringOrNull as awesn1DecodeToStringOrNull
import at.asitplus.awesn1.encoding.decodeToTeletextString as awesn1DecodeToTeletextString
import at.asitplus.awesn1.encoding.decodeToUInt as awesn1DecodeToUInt
import at.asitplus.awesn1.encoding.decodeToUIntOrNull as awesn1DecodeToUIntOrNull
import at.asitplus.awesn1.encoding.decodeToULong as awesn1DecodeToULong
import at.asitplus.awesn1.encoding.decodeToULongOrNull as awesn1DecodeToULongOrNull
import at.asitplus.awesn1.encoding.decodeToUniversalString as awesn1DecodeToUniversalString
import at.asitplus.awesn1.encoding.decodeToUnrestrictedString as awesn1DecodeToUnrestrictedString
import at.asitplus.awesn1.encoding.decodeToUtf8String as awesn1DecodeToUtf8String
import at.asitplus.awesn1.encoding.decodeToVideotexString as awesn1DecodeToVideotexString
import at.asitplus.awesn1.encoding.decodeToVisibleString as awesn1DecodeToVisibleString
import at.asitplus.awesn1.encoding.decodeUtcTimeFromAsn1ContentBytes as awesn1DecodeUtcTimeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.readNull as awesn1ReadNull
import at.asitplus.awesn1.encoding.readNullOrNull as awesn1ReadNullOrNull
import at.asitplus.awesn1.io.readAsn1Element as awesn1ReadAsn1Element
import at.asitplus.awesn1.io.readFullyToAsn1Elements as awesn1ReadFullyToAsn1Elements
import kotlinx.io.Source
import kotlin.experimental.and
import kotlin.time.Instant

@Deprecated(
    "Use a ByteArray or a kotlinx.io Source directly instead.",
    ReplaceWith("source.readAsn1Element().first.also { require(source.exhausted()) }"),
    DeprecationLevel.ERROR
)
fun at.asitplus.awesn1.Asn1Element.Companion.parse(input: ByteIterator): Asn1Element =
    parse(mutableListOf<Byte>().also { while (input.hasNext()) it.add(input.nextByte()) }.toByteArray())

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.parse(source).",
    ReplaceWith("at.asitplus.awesn1.Asn1Element.parse(source)")
)
@Throws(Asn1Exception::class)
fun at.asitplus.awesn1.Asn1Element.Companion.parse(source: ByteArray): Asn1Element =
    at.asitplus.awesn1.Asn1Element.parse(source)

@Deprecated(
    "Use a ByteArray or a kotlinx.io Source directly instead.",
    ReplaceWith("source.readFullyToAsn1Elements().first"),
    DeprecationLevel.ERROR
)
fun at.asitplus.awesn1.Asn1Element.Companion.parseAll(input: ByteIterator): List<Asn1Element> =
    parseAll(mutableListOf<Byte>().also { while (input.hasNext()) it.add(input.nextByte()) }.toByteArray())

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.parseAll(source).",
    ReplaceWith("at.asitplus.awesn1.Asn1Element.parseAll(source)")
)
@Throws(Asn1Exception::class)
fun at.asitplus.awesn1.Asn1Element.Companion.parseAll(source: ByteArray): List<Asn1Element> =
    at.asitplus.awesn1.Asn1Element.parseAll(source)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.parseFirst(source).",
    ReplaceWith("at.asitplus.awesn1.Asn1Element.parseFirst(source)")
)
@Throws(Asn1Exception::class)
fun at.asitplus.awesn1.Asn1Element.Companion.parseFirst(source: ByteArray): Pair<Asn1Element, ByteArray> =
    at.asitplus.awesn1.Asn1Element.parseFirst(source)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.readFullyToAsn1Elements().",
    ReplaceWith("at.asitplus.awesn1.io.readFullyToAsn1Elements(this)")
)
fun Source.readFullyToAsn1Elements(): Pair<List<Asn1Element>, Long> = awesn1ReadFullyToAsn1Elements()

@Deprecated(
    "Moved to at.asitplus.awesn1.io.readAsn1Element().",
    ReplaceWith("at.asitplus.awesn1.io.readAsn1Element(this)")
)
fun Source.readAsn1Element(): Pair<Asn1Element, Long> = awesn1ReadAsn1Element()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToBoolean().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToBoolean(this, assertTag)")
)
fun Asn1Primitive.decodeToBoolean(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.BOOL) =
    awesn1DecodeToBoolean(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToBooleanOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToBooleanOrNull(this, assertTag)")
)
fun Asn1Primitive.decodeToBooleanOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.BOOL) =
    awesn1DecodeToBooleanOrNull(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToEnumOrdinal().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToEnumOrdinal(this, assertTag)")
)
fun Asn1Primitive.decodeToEnumOrdinal(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.ENUM) =
    awesn1DecodeToEnumOrdinal(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToEnumOrdinalOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToEnumOrdinalOrNull(this, assertTag)")
)
inline fun Asn1Primitive.decodeToEnumOrdinalOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.ENUM) =
    awesn1DecodeToEnumOrdinalOrNull(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToEnum().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToEnum(this, assertTag)")
)
inline fun <reified E : Enum<E>> Asn1Primitive.decodeToEnum(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.ENUM): E =
    awesn1DecodeToEnum(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToEnumOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToEnumOrNull(this, assertTag)")
)
inline fun <reified E : Enum<E>> Asn1Primitive.decodeToEnumOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.ENUM): E? =
    awesn1DecodeToEnumOrNull(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToInt().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToInt(this, assertTag)"))
fun Asn1Primitive.decodeToInt(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToInt(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToIntOrNull().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToIntOrNull(this, assertTag)"))
fun Asn1Primitive.decodeToIntOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToIntOrNull(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToLong().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToLong(this, assertTag)"))
fun Asn1Primitive.decodeToLong(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToLong(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToLongOrNull().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToLongOrNull(this, assertTag)"))
inline fun Asn1Primitive.decodeToLongOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToLongOrNull(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToUInt().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToUInt(this, assertTag)"))
fun Asn1Primitive.decodeToUInt(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToUInt(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToUIntOrNull().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToUIntOrNull(this, assertTag)"))
inline fun Asn1Primitive.decodeToUIntOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToUIntOrNull(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToULong().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToULong(this, assertTag)"))
fun Asn1Primitive.decodeToULong(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToULong(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToULongOrNull().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToULongOrNull(this, assertTag)"))
inline fun Asn1Primitive.decodeToULongOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToULongOrNull(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToAsn1Integer().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToAsn1Integer(this, assertTag)")
)
fun Asn1Primitive.decodeToAsn1Integer(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToAsn1Integer(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToAsn1IntegerOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToAsn1IntegerOrNull(this, assertTag)")
)
inline fun Asn1Primitive.decodeToAsn1IntegerOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.INT) =
    awesn1DecodeToAsn1IntegerOrNull(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes).",
    ReplaceWith("at.asitplus.awesn1.Asn1Integer.decodeFromAsn1ContentBytes(bytes)")
)
fun at.asitplus.awesn1.Asn1Integer.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Asn1Integer =
    at.asitplus.awesn1.Asn1Integer.decodeFromAsn1ContentBytes(bytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToAsn1Real().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToAsn1Real(this, assertTag)")
)
fun Asn1Primitive.decodeToAsn1Real(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.REAL) =
    awesn1DecodeToAsn1Real(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToAsn1RealOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToAsn1RealOrNull(this, assertTag)")
)
inline fun Asn1Primitive.decodeToAsn1RealOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.REAL): Asn1Real? =
    awesn1DecodeToAsn1RealOrNull(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToDouble().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToDouble(this, assertTag)"))
fun Asn1Primitive.decodeToDouble(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.REAL) =
    awesn1DecodeToDouble(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToDoubleOrNull().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToDoubleOrNull(this, assertTag)"))
inline fun Asn1Primitive.decodeToDoubleOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.REAL) =
    awesn1DecodeToDoubleOrNull(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToFloat().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToFloat(this, assertTag)"))
inline fun Asn1Primitive.decodeToFloat(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.REAL) =
    awesn1DecodeToFloat(assertTag)

@Deprecated("Moved to at.asitplus.awesn1.encoding.decodeToFloatOrNull().", ReplaceWith("at.asitplus.awesn1.encoding.decodeToFloatOrNull(this, assertTag)"))
inline fun Asn1Primitive.decodeToFloatOrNull(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.REAL) =
    awesn1DecodeToFloatOrNull(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.asAsn1String().",
    ReplaceWith("at.asitplus.awesn1.encoding.asAsn1String(this)")
)
fun Asn1Primitive.asAsn1String(): Asn1String = awesn1AsAsn1String()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToUtf8String().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToUtf8String(this, assertTag)")
)
inline fun Asn1Primitive.decodeToUtf8String(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_UTF8) =
    awesn1DecodeToUtf8String(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToUniversalString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToUniversalString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToUniversalString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_UNIVERSAL) =
    awesn1DecodeToUniversalString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToIa5String().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToIa5String(this, assertTag)")
)
inline fun Asn1Primitive.decodeToIa5String(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_IA5) =
    awesn1DecodeToIa5String(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToBmpString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToBmpString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToBmpString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_BMP) =
    awesn1DecodeToBmpString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToTeletextString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToTeletextString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToTeletextString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_T61) =
    awesn1DecodeToTeletextString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToPrintableString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToPrintableString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToPrintableString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_PRINTABLE) =
    awesn1DecodeToPrintableString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToNumericString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToNumericString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToNumericString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_NUMERIC) =
    awesn1DecodeToNumericString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToVisibleString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToVisibleString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToVisibleString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_VISIBLE) =
    awesn1DecodeToVisibleString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToGeneralString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToGeneralString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToGeneralString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_GENERAL) =
    awesn1DecodeToGeneralString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToGraphicString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToGraphicString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToGraphicString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_GRAPHIC) =
    awesn1DecodeToGraphicString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToUnrestrictedString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToUnrestrictedString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToUnrestrictedString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_UNRESTRICTED) =
    awesn1DecodeToUnrestrictedString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToVideotexString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToVideotexString(this, assertTag)")
)
inline fun Asn1Primitive.decodeToVideotexString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.STRING_VIDEOTEX) =
    awesn1DecodeToVideotexString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToString().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToString(this)")
)
fun Asn1Primitive.decodeToString() = awesn1DecodeToString()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToStringOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToStringOrNull(this)")
)
fun Asn1Primitive.decodeToStringOrNull() = awesn1DecodeToStringOrNull()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToInstant().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToInstant(this)")
)
fun Asn1Primitive.decodeToInstant() = awesn1DecodeToInstant()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeToInstantOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeToInstantOrNull(this)")
)
fun Asn1Primitive.decodeToInstantOrNull() = awesn1DecodeToInstantOrNull()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.asAsn1BitString().",
    ReplaceWith("at.asitplus.awesn1.encoding.asAsn1BitString(this, assertTag)")
)
fun Asn1Primitive.asAsn1BitString(assertTag: at.asitplus.awesn1.Asn1Element.Tag = at.asitplus.awesn1.Asn1Element.Tag.BIT_STRING) =
    awesn1AsAsn1BitString(assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.readNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.readNull(this)")
)
fun Asn1Primitive.readNull() = awesn1ReadNull()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.readNullOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.readNullOrNull(this)")
)
fun Asn1Primitive.readNullOrNull() = awesn1ReadNullOrNull()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decode().",
    ReplaceWith("at.asitplus.awesn1.encoding.decode(this, assertTag, transform)")
)
inline fun <reified T> Asn1Primitive.decode(assertTag: ULong, noinline transform: (content: ByteArray) -> T): T =
    awesn1Decode(assertTag, transform)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decode().",
    ReplaceWith("at.asitplus.awesn1.encoding.decode(this, assertTag, transform)")
)
inline fun <reified T> Asn1Primitive.decode(
    assertTag: at.asitplus.awesn1.Asn1Element.Tag,
    noinline transform: (content: ByteArray) -> T
): T = awesn1Decode(assertTag, transform)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeOrNull(this, tag, transform)")
)
inline fun <reified T> Asn1Primitive.decodeOrNull(tag: ULong, noinline transform: (content: ByteArray) -> T) =
    awesn1DecodeOrNull(tag, transform)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeUtcTimeFromAsn1ContentBytes(input).",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeUtcTimeFromAsn1ContentBytes(input)")
)
fun Instant.Companion.decodeUtcTimeFromAsn1ContentBytes(input: ByteArray): Instant =
    awesn1DecodeUtcTimeFromAsn1ContentBytes(input)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeGeneralizedTimeFromAsn1ContentBytes(bytes).",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeGeneralizedTimeFromAsn1ContentBytes(bytes)")
)
fun Instant.Companion.decodeGeneralizedTimeFromAsn1ContentBytes(bytes: ByteArray): Instant =
    awesn1DecodeGeneralizedTimeFromAsn1ContentBytes(bytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes).",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes)")
)
fun Int.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Int =
    awesn1DecodeFromAsn1ContentBytes(bytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes).",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes)")
)
fun Long.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Long =
    awesn1DecodeFromAsn1ContentBytes(bytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes).",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes)")
)
fun UInt.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): UInt =
    awesn1DecodeFromAsn1ContentBytes(bytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes).",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes)")
)
fun ULong.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): ULong =
    awesn1DecodeFromAsn1ContentBytes(bytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes).",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes)")
)
fun Boolean.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Boolean =
    awesn1DecodeFromAsn1ContentBytes(bytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes).",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes(bytes)")
)
fun String.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray) =
    awesn1DecodeFromAsn1ContentBytes(bytes)

@Deprecated(
    "Moved to awesn1 parsing APIs; there is no direct public replacement for this specific helper.",
    ReplaceWith("readAsn1Element().first.tag")
)
fun Source.readAsn1Tag(): at.asitplus.awesn1.Asn1Element.Tag {
    val firstByte = readByte()
    val constructed = (firstByte and 0x20) != 0.toByte()
    val tagClass = TagClass.fromByte(firstByte).getOrThrow()
    val shortTagNumber = (firstByte and 0x1F).toUByte()
    val tagValue = if (shortTagNumber <= 30u) shortTagNumber.toULong() else decodeAsn1VarULong().first
    return at.asitplus.awesn1.Asn1Element.Tag(tagValue, constructed = constructed, tagClass = tagClass)
}
