package at.asitplus.signum.indispensable.asn1

import java.math.BigInteger

private fun at.asitplus.awesn1.Asn1Integer.Sign.toJavaBigIntegerSign() = when (this) {
    at.asitplus.awesn1.Asn1Integer.Sign.POSITIVE -> 1
    at.asitplus.awesn1.Asn1Integer.Sign.NEGATIVE -> -1
}

fun Asn1Integer.toJavaBigInteger() =
    BigInteger(this.sign.toJavaBigIntegerSign(), this.magnitude)

fun BigInteger.toAsn1Integer() =
    Asn1Integer.fromByteArray(
        magnitude = this.abs().toByteArray(),
        sign = if (this.signum() < 0) at.asitplus.awesn1.Asn1Integer.Sign.NEGATIVE
        else at.asitplus.awesn1.Asn1Integer.Sign.POSITIVE)
