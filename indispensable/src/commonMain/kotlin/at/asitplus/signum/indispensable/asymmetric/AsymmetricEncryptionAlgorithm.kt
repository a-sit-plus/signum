package at.asitplus.signum.indispensable.asymmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.AlgorithmRegistry
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.WithRsaEncryptionPadding
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration

interface RsaEncryptionPadding : Enumerable {
    companion object : Enumeration<RsaEncryptionPadding> {

        override val entries: List<RsaEncryptionPadding>
            get() {
                return AlgorithmRegistry.asymmetricRsaPaddings
            }

        fun register(padding: RsaEncryptionPadding): RsaEncryptionPadding =
            AlgorithmRegistry.registerAsymmetricRsaPadding(padding)

        fun fromString(string: String) = entries.firstOrNull { it.toString() == string }
    }
}

@HazardousMaterials("This padding scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
data object Pkcs1RsaEncryptionPadding : RsaEncryptionPadding {
    override fun toString(): String = "PKCS1"
}

@HazardousMaterials("This is almost always insecure and can leak your private key!")
data object NoRsaEncryptionPadding : RsaEncryptionPadding {
    override fun toString(): String = "NONE"
}

open class OaepRsaEncryptionPadding(val digest: Digest) : RsaEncryptionPadding {
    override fun toString(): String = "OAEP_${digest.name}"

    data object Sha1 : OaepRsaEncryptionPadding(Digest.SHA1)
    data object Sha256 : OaepRsaEncryptionPadding(Digest.SHA256)
    data object Sha384 : OaepRsaEncryptionPadding(Digest.SHA384)
    data object Sha512 : OaepRsaEncryptionPadding(Digest.SHA512)
}

@HazardousMaterials("This padding scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
val RsaEncryptionPadding.Companion.PKCS1: RsaEncryptionPadding get() = Pkcs1RsaEncryptionPadding
@HazardousMaterials("This is almost always insecure and can leak your private key!")
val RsaEncryptionPadding.Companion.NONE: RsaEncryptionPadding get() = NoRsaEncryptionPadding
val RsaEncryptionPadding.Companion.OAEP_SHA1: RsaEncryptionPadding get() = OaepRsaEncryptionPadding.Sha1
val RsaEncryptionPadding.Companion.OAEP_SHA256: RsaEncryptionPadding get() = OaepRsaEncryptionPadding.Sha256
val RsaEncryptionPadding.Companion.OAEP_SHA384: RsaEncryptionPadding get() = OaepRsaEncryptionPadding.Sha384
val RsaEncryptionPadding.Companion.OAEP_SHA512: RsaEncryptionPadding get() = OaepRsaEncryptionPadding.Sha512

interface AsymmetricEncryptionAlgorithm : Enumerable {
    @Deprecated("Use RsaEncryptionAlgorithm.", ReplaceWith("RsaEncryptionAlgorithm"))
    interface RSA : AsymmetricEncryptionAlgorithm {
        val padding: RsaEncryptionPadding
    }

    companion object : Enumeration<AsymmetricEncryptionAlgorithm> {


        override val entries: Iterable<AsymmetricEncryptionAlgorithm>
            get() {
                return AlgorithmRegistry.asymmetricEncryptionAlgorithms
            }

        fun register(algorithm: AsymmetricEncryptionAlgorithm): AsymmetricEncryptionAlgorithm =
            AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(algorithm)

        @Deprecated(
            "Use RsaEncryptionAlgorithm(...) or the companion built-ins.",
            ReplaceWith("RsaEncryptionAlgorithm(padding)")
        )
        val RSA: DeprecatedRsaEncryptionNamespace get() = DeprecatedRsaEncryptionNamespace

        @HazardousMaterials("This is almost always insecure and can leak your private key!")
        @Deprecated("Use AsymmetricEncryptionAlgorithm.RSA_NONE.", ReplaceWith("AsymmetricEncryptionAlgorithm.RSA_NONE"))
        val NoPadding: AsymmetricEncryptionAlgorithm get() = RSA_NONE

        @HazardousMaterials("This padding scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
        @Deprecated("Use AsymmetricEncryptionAlgorithm.RSA_PKCS1.", ReplaceWith("AsymmetricEncryptionAlgorithm.RSA_PKCS1"))
        val Pkcs1Padding: AsymmetricEncryptionAlgorithm get() = RSA_PKCS1
    }
}

open class RsaEncryptionAlgorithm(
    override val padding: RsaEncryptionPadding
) : AsymmetricEncryptionAlgorithm.RSA, WithRsaEncryptionPadding {
    override fun equals(other: Any?): Boolean = other is RsaEncryptionAlgorithm && padding == other.padding
    override fun hashCode(): Int = padding.hashCode()
    override fun toString(): String = "RSA($padding)"
}

@OptIn(HazardousMaterials::class)
val AsymmetricEncryptionAlgorithm.Companion.RSA_NONE: RsaEncryptionAlgorithm get() =
    RsaEncryptionAlgorithm(RsaEncryptionPadding.NONE)
@OptIn(HazardousMaterials::class)
val AsymmetricEncryptionAlgorithm.Companion.RSA_PKCS1: RsaEncryptionAlgorithm get() =
    RsaEncryptionAlgorithm(RsaEncryptionPadding.PKCS1)
val AsymmetricEncryptionAlgorithm.Companion.RSA_OAEP_SHA1: RsaEncryptionAlgorithm get() =
    RsaEncryptionAlgorithm(RsaEncryptionPadding.OAEP_SHA1)
val AsymmetricEncryptionAlgorithm.Companion.RSA_OAEP_SHA256: RsaEncryptionAlgorithm get() =
    RsaEncryptionAlgorithm(RsaEncryptionPadding.OAEP_SHA256)
val AsymmetricEncryptionAlgorithm.Companion.RSA_OAEP_SHA384: RsaEncryptionAlgorithm get() =
    RsaEncryptionAlgorithm(RsaEncryptionPadding.OAEP_SHA384)
val AsymmetricEncryptionAlgorithm.Companion.RSA_OAEP_SHA512: RsaEncryptionAlgorithm get() =
    RsaEncryptionAlgorithm(RsaEncryptionPadding.OAEP_SHA512)

@Deprecated("Use RsaEncryptionAlgorithm and AsymmetricEncryptionAlgorithm companion properties.")
object DeprecatedRsaEncryptionNamespace {
    operator fun invoke(padding: RsaEncryptionPadding) = RsaEncryptionAlgorithm(padding)

    @HazardousMaterials("This is almost always insecure and can leak your private key!")
    val NoPadding: RsaEncryptionAlgorithm get() = AsymmetricEncryptionAlgorithm.RSA_NONE

    @HazardousMaterials("This padding scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
    val Pkcs1Padding: RsaEncryptionAlgorithm get() = AsymmetricEncryptionAlgorithm.RSA_PKCS1

    object OAEP {
        val SHA1: RsaEncryptionAlgorithm get() = AsymmetricEncryptionAlgorithm.RSA_OAEP_SHA1
        val SHA256: RsaEncryptionAlgorithm get() = AsymmetricEncryptionAlgorithm.RSA_OAEP_SHA256
        val SHA384: RsaEncryptionAlgorithm get() = AsymmetricEncryptionAlgorithm.RSA_OAEP_SHA384
        val SHA512: RsaEncryptionAlgorithm get() = AsymmetricEncryptionAlgorithm.RSA_OAEP_SHA512
    }
}

@Deprecated("Use RsaEncryptionPadding.", ReplaceWith("RsaEncryptionPadding"))
typealias RSAPadding = RsaEncryptionPadding
