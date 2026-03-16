package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable

interface Awesn1Backed<out T, A : Asn1Element, out D> : Asn1Encodable<A>
        where T : Asn1Encodable<out A> {
    val raw: T

    override fun encodeToTlv(): A = raw.encodeToTlv()
}
