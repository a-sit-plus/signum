package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.KmmResult
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable

/**
 * Either type containing:
 * * **on success:** the parsed [Success.value] with semantics attached
 * * **on failure:** the [Failure.rawAsn1Value], which is a deep copy of the non-parsable source element
 *
 * @param T the type of the parsed [Asn1Encodable]
 *
 * @see Asn1Element
 *
 */
sealed class AttestationValue<out A : Asn1Encodable<*>>(override val tagged: AuthorizationList.Tagged) :
    AuthorizationList.Tagged.WithTag<Asn1Element> {
    class Success<out T : Asn1Encodable<*>> internal constructor(val value: T, tagged: AuthorizationList.Tagged) :
        AttestationValue<T>(tagged) {
        override fun encodeToTlv(): Asn1Element = value.encodeToTlv()

    }

    class Failure<E : Asn1Element> internal constructor(
        val elementName: String,
        tagged: AuthorizationList.Tagged,
        source: E
    ) : AttestationValue<Asn1Encodable<*>>(tagged) {
        val rawAsn1Value = source.copy()
        override fun encodeToTlv(): Asn1Element = rawAsn1Value
    }

    inline fun <S,F> fold(onSuccess: (A)->S,
                        onFailure: (String, AuthorizationList.Tagged, Asn1Element)->F) = when(this){
        is Success -> onSuccess(value)
        is Failure<*> -> onFailure(elementName, tagged, rawAsn1Value)
    }

    @Deprecated("this needs to be replaced with a proper check!")
    fun getOrNull() = if(this is Success) value else null
}

internal inline fun <reified E : Asn1Element, reified T : Asn1Encodable<E>, reified A : AttestationValue<T>> E.parsing(
    tagged: AuthorizationList.Tagged,
    block: () -> T
): AttestationValue<T> = catchingUnwrapped {
    block.invoke()
}.fold(
    onSuccess = { AttestationValue.Success(it, tagged) },
    onFailure = { AttestationValue.Failure(E::class.simpleName!!, tagged, this) as AttestationValue<T> }
)
