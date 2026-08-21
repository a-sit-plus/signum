package at.asitplus.signum.dsl

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.supreme.dsl.DSL

open class InMemorySignerConfiguration: DSL.Data() {

}
class EphemeralSignerConfiguration: InMemorySignerConfiguration() {
    val _algSpecific = subclassOf<AlgorithmSpecific>("ALG_SPECIFIC_CONFIG")
    abstract class AlgorithmSpecific : DSL.Data()
}

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

class JVMEphemeralConfiguration : DSL.Data() {
    /** The JCA provider to use. Defaults to [JCAProviderRef.None] (no particular provider specified). */
    var provider: JCAProviderRef = JCAProviderRef.None
}

val InMemorySignerConfiguration.jvm get() =
    childOrDefault("JVM", ::JVMEphemeralConfiguration)

val EphemeralSignerConfiguration.ec get() =
    _algSpecific.option("SIGNUM_ECDSA", ::EphemeralECDSAConfiguration)

val EphemeralSignerConfiguration.rsa get() =
    _algSpecific.option("SIGNUM_RSA", ::EphemeralRSAConfiguration)
