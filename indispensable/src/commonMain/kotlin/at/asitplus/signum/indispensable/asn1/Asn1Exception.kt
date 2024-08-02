package at.asitplus.signum.indispensable.asn1

import at.asitplus.catching
import at.asitplus.wrapping

open class Asn1Exception(message: String?, cause: Throwable?) : Throwable(message, cause) {
    constructor(message: String) : this(message, null)
    constructor(throwable: Throwable) : this(null, throwable)
}

class Asn1TagMismatchException(val expected: UByte, val actual: UByte, detailedMessage: String? = null) :
    Asn1Exception((detailedMessage?.let { "$it " } ?: "") + "Expected tag $expected, is: $actual")

class Asn1StructuralException(message: String) : Asn1Exception(message)

class Asn1OidException(message: String, val oid: ObjectIdentifier) : Asn1Exception(message)

/**
 * Runs [block] inside [catching] and encapsulates any thrown exception in an [Asn1Exception] unless it already is one
 */
@Throws(Asn1Exception::class)
inline fun <reified R> runRethrowing(block: () -> R) = wrapping(asA = ::Asn1Exception, block).getOrThrow()