package at.asitplus.signum.indispensable.asn1

import at.asitplus.catching
import at.asitplus.catchingUnwrappedAs

open class Asn1Exception(message: String?, cause: Throwable?) : Throwable(message, cause) {
    constructor(message: String) : this(message, null)
    constructor(throwable: Throwable) : this(null, throwable)
}

class Asn1TagMismatchException(
    val expected: Asn1Element.Tag,
    val actual: Asn1Element.Tag,
    detailedMessage: String? = null
) :
    Asn1Exception((detailedMessage?.let { "$it " } ?: "") + "Expected tag $expected, is: $actual")

class Asn1StructuralException(message: String, cause: Throwable? = null) : Asn1Exception(message, cause)

class Asn1OidException(message: String, val oid: ObjectIdentifier) : Asn1Exception(message)

/**
 * Runs [block] inside [catching] and encapsulates any thrown exception in an [Asn1Exception] unless it already is one
 */
@Throws(Asn1Exception::class)
inline fun <reified R> runRethrowing(block: () -> R) = catchingUnwrappedAs(::Asn1Exception, block).getOrThrow()

/**
 * Decodes this ASN.1 structure using the provided [decoder] lambda, rethrowing any caught exception
 * as an [Asn1Exception].
 * This is a wrapper around [Asn1Structure.decodeAs] that ensures exceptions thrown during decoding are
 * consistently rethrown as [Asn1Exception], using the [runRethrowing] utility.
 */
inline fun <reified R> Asn1Structure.decodeRethrowing(
    requireFullConsumption: Boolean = true,
    decoder: Asn1Structure.Iterator.() -> R
) =
    runRethrowing {
        this@decodeRethrowing.decodeAs(requireFullConsumption, decoder)
    }