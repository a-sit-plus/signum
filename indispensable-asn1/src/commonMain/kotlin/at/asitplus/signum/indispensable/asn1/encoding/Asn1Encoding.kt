@file:Suppress("unused")

package at.asitplus.signum.indispensable.asn1.encoding

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1BitString
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Null
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Real
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1Set
import at.asitplus.signum.indispensable.asn1.BitSet
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.awesn1.encoding.encodeToAsn1BitStringContentBytes as awesn1EncodeToAsn1BitStringContentBytes
import at.asitplus.awesn1.encoding.encodeToAsn1BitStringPrimitive as awesn1EncodeToAsn1BitStringPrimitive
import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes as awesn1EncodeToAsn1ContentBytes
import at.asitplus.awesn1.encoding.encodeToAsn1GeneralizedTimePrimitive as awesn1EncodeToAsn1GeneralizedTimePrimitive
import at.asitplus.awesn1.encoding.encodeToAsn1OctetStringPrimitive as awesn1EncodeToAsn1OctetStringPrimitive
import at.asitplus.awesn1.encoding.encodeToAsn1Primitive as awesn1EncodeToAsn1Primitive
import at.asitplus.awesn1.encoding.encodeToAsn1PrimitiveOrNull as awesn1EncodeToAsn1PrimitiveOrNull
import at.asitplus.awesn1.encoding.encodeToAsn1UtcTimePrimitive as awesn1EncodeToAsn1UtcTimePrimitive
import kotlin.time.Instant

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.Asn1TreeBuilder.",
    ReplaceWith("at.asitplus.awesn1.encoding.Asn1TreeBuilder")
)
typealias Asn1TreeBuilder = at.asitplus.awesn1.encoding.Asn1TreeBuilder

@Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.", ReplaceWith("at.asitplus.awesn1.encoding.Asn1"))
object Asn1 {
    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.Sequence(root).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Sequence(root)")
    )
    fun Sequence(root: Asn1TreeBuilder.() -> Unit): Asn1Sequence =
        at.asitplus.awesn1.encoding.Asn1.Sequence(root)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.SequenceOrNull(root).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.SequenceOrNull(root)")
    )
    fun SequenceOrNull(root: Asn1TreeBuilder.() -> Unit): Asn1Sequence? =
        at.asitplus.awesn1.encoding.Asn1.SequenceOrNull(root)

    @Deprecated("Use awesn1 APIs directly.")
    fun SequenceSafe(root: Asn1TreeBuilder.() -> Unit): KmmResult<Asn1Sequence> = catching { Sequence(root) }

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.Set(root).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Set(root)")
    )
    fun Set(root: Asn1TreeBuilder.() -> Unit): Asn1Set =
        at.asitplus.awesn1.encoding.Asn1.Set(root)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.SetOrNull(root).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.SetOrNull(root)")
    )
    fun SetOrNull(root: Asn1TreeBuilder.() -> Unit): Asn1Set? =
        at.asitplus.awesn1.encoding.Asn1.SetOrNull(root)

    @Deprecated("Use awesn1 APIs directly.")
    fun SetSafe(root: Asn1TreeBuilder.() -> Unit): KmmResult<Asn1Set> = catching { Set(root) }

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.SetOf(root).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.SetOf(root)")
    )
    fun SetOf(root: Asn1TreeBuilder.() -> Unit): Asn1Set =
        at.asitplus.awesn1.encoding.Asn1.SetOf(root)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.SetOfOrNull(root).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.SetOfOrNull(root)")
    )
    fun SetOfOrNull(root: Asn1TreeBuilder.() -> Unit): Asn1Set? =
        at.asitplus.awesn1.encoding.Asn1.SetOfOrNull(root)

    @Deprecated("Use awesn1 APIs directly.")
    fun SetOfSafe(root: Asn1TreeBuilder.() -> Unit): KmmResult<Asn1Set> = catching { SetOf(root) }

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.ExplicitlyTagged(tag, root).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.ExplicitlyTagged(tag, root)")
    )
    fun ExplicitlyTagged(tag: ULong, root: Asn1TreeBuilder.() -> Unit): Asn1ExplicitlyTagged =
        at.asitplus.awesn1.encoding.Asn1.ExplicitlyTagged(tag, root)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.ExplicitlyTaggedOrNull(tag, root).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.ExplicitlyTaggedOrNull(tag, root)")
    )
    fun ExplicitlyTaggedOrNull(tag: ULong, root: Asn1TreeBuilder.() -> Unit): Asn1ExplicitlyTagged? =
        at.asitplus.awesn1.encoding.Asn1.ExplicitlyTaggedOrNull(tag, root)

    @Deprecated("Use awesn1 APIs directly.")
    fun ExplicitlyTaggedSafe(tag: ULong, root: Asn1TreeBuilder.() -> Unit): KmmResult<Asn1ExplicitlyTagged> =
        catching { ExplicitlyTagged(tag, root) }

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.Enumerated(ordinal).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Enumerated(ordinal)")
    )
    fun Enumerated(ordinal: Long): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Enumerated(ordinal)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.Enumerated(ordinal).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Enumerated(ordinal)")
    )
    fun Enumerated(ordinal: Int): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Enumerated(ordinal)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.Enumerated(enum).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Enumerated(enum)")
    )
    fun Enumerated(enum: Enum<*>): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Enumerated(enum)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Bool(value).", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Bool(value)"))
    fun Bool(value: Boolean): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Bool(value)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Int(value).", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Int(value)"))
    fun Int(value: Int): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Int(value)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Int(value).", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Int(value)"))
    fun Int(value: Long): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Int(value)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Int(value).", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Int(value)"))
    fun Int(value: UInt): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Int(value)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Int(value).", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Int(value)"))
    fun Int(value: ULong): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Int(value)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Int(value).", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Int(value)"))
    fun Int(value: Asn1Integer): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Int(value)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Real(value).", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Real(value)"))
    fun Real(value: Float): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Real(value)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Real(value).", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Real(value)"))
    fun Real(value: Double): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Real(value)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.OctetString(bytes).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.OctetString(bytes)")
    )
    fun OctetString(bytes: ByteArray): Asn1PrimitiveOctetString = at.asitplus.awesn1.encoding.Asn1.OctetString(bytes)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.BitString(bytes).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.BitString(bytes)")
    )
    fun BitString(bytes: ByteArray): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.BitString(bytes)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.BitString(bitSet).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.BitString(bitSet)")
    )
    fun BitString(bitSet: BitSet): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.BitString(bitSet)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.Utf8String(value).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Utf8String(value)")
    )
    fun Utf8String(value: String): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Utf8String(value)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.PrintableString(value).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.PrintableString(value)")
    )
    fun PrintableString(value: String): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.PrintableString(value)

    @Deprecated("Moved to at.asitplus.awesn1.encoding.Asn1.Null().", ReplaceWith("at.asitplus.awesn1.encoding.Asn1.Null()"))
    fun Null(): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.Null()

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.UtcTime(value).",
        ReplaceWith("Asn1.UtcTime(value)", "at.asitplus.awesn1.encoding.Asn1")
    )
    fun UtcTime(value: Instant): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.UtcTime(value)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.GeneralizedTime(value).",
        ReplaceWith("Asn1.GeneralizedTime(value)", "at.asitplus.awesn1.encoding.Asn1")
    )
    fun GeneralizedTime(value: Instant): Asn1Primitive = at.asitplus.awesn1.encoding.Asn1.GeneralizedTime(value)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.OctetStringEncapsulating(init).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.OctetStringEncapsulating(init)")
    )
    fun OctetStringEncapsulating(init: Asn1TreeBuilder.() -> Unit): Asn1EncapsulatingOctetString =
        at.asitplus.awesn1.encoding.Asn1.OctetStringEncapsulating(init)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.ImplicitTag(tagNum, tagClass).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.ImplicitTag(tagNum, tagClass)")
    )
    fun ImplicitTag(tagNum: ULong, tagClass: TagClass = TagClass.CONTEXT_SPECIFIC): at.asitplus.awesn1.Asn1Element.Tag =
        at.asitplus.awesn1.encoding.Asn1.ImplicitTag(tagNum, tagClass)

    @Deprecated(
        "Moved to at.asitplus.awesn1.encoding.Asn1.ExplicitTag(tagNum).",
        ReplaceWith("at.asitplus.awesn1.encoding.Asn1.ExplicitTag(tagNum)")
    )
    fun ExplicitTag(tagNum: ULong): at.asitplus.awesn1.Asn1Element.Tag =
        at.asitplus.awesn1.encoding.Asn1.ExplicitTag(tagNum)
}

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)")
)
fun Boolean.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun Int.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun Long.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun UInt.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun ULong.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun Enum<*>.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun Asn1Integer.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun Asn1Real.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun Double.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1PrimitiveOrNull().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1PrimitiveOrNull(this)"))
fun Double.encodeToAsn1PrimitiveOrNull(): Asn1Primitive? = awesn1EncodeToAsn1PrimitiveOrNull()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun Float.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1PrimitiveOrNull().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1PrimitiveOrNull(this)"))
fun Float.encodeToAsn1PrimitiveOrNull(): Asn1Primitive? = awesn1EncodeToAsn1PrimitiveOrNull()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1Primitive().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1Primitive(this)"))
fun String.encodeToAsn1Primitive(): Asn1Primitive = awesn1EncodeToAsn1Primitive()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToAsn1OctetStringPrimitive().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1OctetStringPrimitive(this)")
)
fun ByteArray.encodeToAsn1OctetStringPrimitive(): Asn1PrimitiveOctetString = awesn1EncodeToAsn1OctetStringPrimitive()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToAsn1BitStringPrimitive().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1BitStringPrimitive(this)")
)
fun ByteArray.encodeToAsn1BitStringPrimitive(): Asn1Primitive = awesn1EncodeToAsn1BitStringPrimitive()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToAsn1BitStringContentBytes().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1BitStringContentBytes(this)")
)
fun ByteArray.encodeToAsn1BitStringContentBytes(): ByteArray = awesn1EncodeToAsn1BitStringContentBytes()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes(this)")
)
fun Boolean.encodeToAsn1ContentBytes(): ByteArray = awesn1EncodeToAsn1ContentBytes()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes(this)"))
fun Int.encodeToAsn1ContentBytes(): ByteArray = awesn1EncodeToAsn1ContentBytes()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes(this)"))
fun Long.encodeToAsn1ContentBytes(): ByteArray = awesn1EncodeToAsn1ContentBytes()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes(this)"))
fun UInt.encodeToAsn1ContentBytes(): ByteArray = awesn1EncodeToAsn1ContentBytes()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes(this)"))
fun ULong.encodeToAsn1ContentBytes(): ByteArray = awesn1EncodeToAsn1ContentBytes()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes(this)"))
fun Enum<*>.encodeToAsn1ContentBytes(): ByteArray = awesn1EncodeToAsn1ContentBytes()

@Deprecated("Moved to at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes().", ReplaceWith("at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes(this)"))
fun Asn1Integer.encodeToAsn1ContentBytes(): ByteArray = awesn1EncodeToAsn1ContentBytes()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToAsn1UtcTimePrimitive().",
    ReplaceWith("encodeToAsn1UtcTimePrimitive(this)", "at.asitplus.awesn1.encoding.encodeToAsn1UtcTimePrimitive")
)
fun Instant.encodeToAsn1UtcTimePrimitive(): Asn1Primitive = awesn1EncodeToAsn1UtcTimePrimitive()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToAsn1GeneralizedTimePrimitive().",
    ReplaceWith("encodeToAsn1GeneralizedTimePrimitive(this)", "at.asitplus.awesn1.encoding.encodeToAsn1GeneralizedTimePrimitive")
)
fun Instant.encodeToAsn1GeneralizedTimePrimitive(): Asn1Primitive = awesn1EncodeToAsn1GeneralizedTimePrimitive()
