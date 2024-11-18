package at.asitplus.signum.indispensable.asn1

import java.math.BigInteger

private fun Asn1Integer.Sign.toJavaBigIntegerSign() = when (this) {
    Asn1Integer.Sign.POSITIVE -> 1
    Asn1Integer.Sign.NEGATIVE -> -1
}

fun Asn1Integer.toJavaBigInteger() =
    BigInteger(this.sign.toJavaBigIntegerSign(), this.magnitude)

fun BigInteger.toAsn1Integer() =
    Asn1Integer.fromByteArray(
        magnitude = this.abs().toByteArray(),
        sign = if (this.signum() < 0) Asn1Integer.Sign.NEGATIVE else Asn1Integer.Sign.POSITIVE)
