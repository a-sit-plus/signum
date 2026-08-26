package at.asitplus.signum.dsl

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.sign.RSAAlgorithm

class EphemeralECDSAConfiguration : EphemeralSignerConfiguration.AlgorithmSpecific() {
    /** The curve to operate on. Defaults to [secp256r1][ECCurve.SECP_256_R_1]. */
    var curve: ECCurve = ECCurve.SECP_256_R_1
    /** The digest to sign over. Explicit `null` to sign over raw input. Omit to derive from curve. */
    internal var _digestSpecified = false
    var digest: WellKnownDigest? = null
        get() = if (_digestSpecified) field else curve.nativeDigest
        set(value) { field = value; _digestSpecified = true }
}

class EphemeralRSAConfiguration : EphemeralSignerConfiguration.AlgorithmSpecific() {
    /** The digest to sign over. Defaults to [SHA384][WellKnownDigest.SHA384]. */
    var digest : WellKnownDigest = WellKnownDigest.SHA512
    /** The padding algorithm to use. Defaults to [PSS][RSAAlgorithm.Padding.PSS]. */
    var padding : RSAAlgorithm.Padding = RSAAlgorithm.Padding.PSS
    /** The bit size of the generated key. Defaults to 3072 bits. */
    var bits: Int = 3072
}

val EphemeralSignerConfiguration.ec get() =
    _algSpecific.option("SIGNUM_ECDSA", ::EphemeralECDSAConfiguration)

val EphemeralSignerConfiguration.rsa get() =
    _algSpecific.option("SIGNUM_RSA", ::EphemeralRSAConfiguration)
