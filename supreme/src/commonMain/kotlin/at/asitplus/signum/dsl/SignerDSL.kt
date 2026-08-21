package at.asitplus.signum.dsl

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import com.ionspin.kotlin.bignum.integer.BigInteger

/** DSL for configuring a signing key.
 *
 * Defaults to an elliptic-curve key with a reasonable default configuration.
 *
 * @see ec
 * @see rsa
 */
open class SigningKeyConfiguration internal constructor() : DSL.Data() {

    open class AlgorithmSpecific internal constructor() : DSL.Data()
    val _algSpecific = subclassOf<DSL.Data>("ALG_SPECIFIC_CONFIG")

    open class ECConfiguration internal constructor() : AlgorithmSpecific() {
        /** The [at.asitplus.signum.indispensable.ECCurve] on which to generate the key. Defaults to [P-256][at.asitplus.signum.indispensable.ECCurve.SECP_256_R_1] */
        var curve: ECCurve = ECCurve.SECP_256_R_1

        private var _digests: Set<Digest?>? = null
        /** The digests supported by the key. If not specified, supports the curve's native digest only. */
        open var digests: Set<Digest?>
            get() = _digests ?: setOf(curve.nativeDigest)
            set(v) { _digests = v }
    }

    open class RSAConfiguration internal constructor() : AlgorithmSpecific() {
        companion object {
            val F0 = BigInteger(3);
            val F4 = BigInteger(65537)
        }


        /** The digests supported by the key. If not specified, defaults to [SHA384][Digest.Companion.SHA384]. */
        open var digests: Set<Digest> = setOf(Digest.SHA384)

        /** The paddings supported by the key. If not specified, defaults to [RSA-PSS][at.asitplus.signum.indispensable.sign.RSAAlgorithm.Padding.PSS]. */
        open var paddings: Set<RSAAlgorithm.Padding> = setOf(RSAAlgorithm.Padding.PSS)

        /** The bit size of the generated key. If not specified, defaults to 3072 bits. */
        var bits: Int = 3072

        /** The public exponent to use. Defaults to F4.
         * This is treated as advisory, and may be ignored by some platforms. */
        var publicExponent: BigInteger = F4
    }
}

/** Generates an elliptic-curve key. */
val SigningKeyConfiguration.ec get() = _algSpecific.defaultOption("EC", SigningKeyConfiguration::ECConfiguration)

/** Generates an RSA key. */
val SigningKeyConfiguration.rsa get() = _algSpecific.option("RSA", SigningKeyConfiguration::RSAConfiguration)