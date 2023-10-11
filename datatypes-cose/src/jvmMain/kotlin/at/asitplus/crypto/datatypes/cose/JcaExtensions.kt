package at.asitplus.crypto.datatypes.cose

val CoseEllipticCurve.jcaName
    get() = when (this) {
        CoseEllipticCurve.P256 -> "P-256"
        CoseEllipticCurve.P384 -> "P-384"
        CoseEllipticCurve.P521 -> "P-521"
    }