package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.josef.JwsAlgorithm.MAC.UNOFFICIAL_HS1
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Since we support only JWS algorithms (with one exception), this class is called what it's called.
 */
@Serializable(with = JwsAlgorithmSerializer::class)
sealed class JwsAlgorithm<D : DataIntegrityAlgorithm>(override val identifier: String, val algorithm: D) :
    JsonWebAlgorithm {


    sealed class Signature(identifier: String, algorithm: SignatureAlgorithm) :
        JwsAlgorithm<SignatureAlgorithm>(identifier, algorithm),
        SpecializedSignatureAlgorithm {

        object ES256 : Signature("ES256", SignatureAlgorithm.ECDSAwithSHA256)
        object ES384 : Signature("ES384", SignatureAlgorithm.ECDSAwithSHA384)
        object ES512 : Signature("ES512", SignatureAlgorithm.ECDSAwithSHA512)

        object PS256 : Signature("PS256", SignatureAlgorithm.RSAwithSHA256andPSSPadding)
        object PS384 : Signature("PS384", SignatureAlgorithm.RSAwithSHA384andPSSPadding)
        object PS512 : Signature("PS512", SignatureAlgorithm.RSAwithSHA512andPSSPadding)

        object RS256 : Signature("RS256", SignatureAlgorithm.RSAwithSHA256andPKCS1Padding)
        object RS384 : Signature("RS384", SignatureAlgorithm.RSAwithSHA384andPKCS1Padding)
        object RS512 : Signature("RS512", SignatureAlgorithm.RSAwithSHA512andPKCS1Padding)

        /** The one exception, which is not a valid JWS algorithm identifier */
        object NON_JWS_SHA1_WITH_RSA : Signature("RS1", SignatureAlgorithm.RSA(Digest.SHA1, RSAPadding.PKCS1))

        /** The curve to create signatures on.
         * This is fixed by RFC7518, as opposed to X.509 where other combinations are possible. */
        val ecCurve: ECCurve?
            get() = when (this) {
                ES256 -> ECCurve.SECP_256_R_1
                ES384 -> ECCurve.SECP_384_R_1
                ES512 -> ECCurve.SECP_521_R_1
                else -> null
            }

        open val digest: Digest?
            get() = when (algorithm) {
                is SignatureAlgorithm.ECDSA -> digest
                is SignatureAlgorithm.RSA -> digest
            }

        companion object {
            val entries: Collection<Signature> = listOf(
                ES256,
                ES384,
                ES512,
                PS256,
                PS384,
                PS512,
                RS256,
                RS384,
                RS512,
                NON_JWS_SHA1_WITH_RSA,
            )
        }

    }

    sealed class MAC(identifier: String, algorithm: MessageAuthenticationCode) :
        JwsAlgorithm<MessageAuthenticationCode>(identifier, algorithm) {
        object HS256 : MAC("HS256", HMAC.SHA256)
        object HS384 : MAC("HS384", HMAC.SHA384)
        object HS512 : MAC("HS512", HMAC.SHA512)
        object UNOFFICIAL_HS1 : MAC("H1", HMAC.SHA1)
        companion object {
            val entries: Collection<MAC> = listOf(
                HS256,
                HS384,
                HS512,
                UNOFFICIAL_HS1,
            )
        }
    }

    companion object {
        val entries: Collection<JwsAlgorithm<*>> = Signature.entries + MAC.entries
    }
}

object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm<*>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsAlgorithm<*>) =
        JwaSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JwsAlgorithm<*> {
        val decoded = decoder.decodeString()
        return JwsAlgorithm.entries.first { it.identifier == decoded }
    }
}

/** Tries to find a matching JWS algorithm. Note that JWS imposes curve restrictions on ECDSA based on the digest. */
fun SignatureAlgorithm.toJwsAlgorithm() = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA -> when (this.digest) {
            Digest.SHA256 -> JwsAlgorithm.Signature.ES256
            Digest.SHA384 -> JwsAlgorithm.Signature.ES384
            Digest.SHA512 -> JwsAlgorithm.Signature.ES512
            else -> throw IllegalArgumentException("ECDSA with ${this.digest} is unsupported by JWS")
        }

        is SignatureAlgorithm.RSA -> when (this.padding) {
            RSAPadding.PKCS1 -> when (this.digest) {
                Digest.SHA1 -> JwsAlgorithm.Signature.NON_JWS_SHA1_WITH_RSA
                Digest.SHA256 -> JwsAlgorithm.Signature.RS256
                Digest.SHA384 -> JwsAlgorithm.Signature.RS384
                Digest.SHA512 -> JwsAlgorithm.Signature.RS512
            }

            RSAPadding.PSS -> when (this.digest) {
                Digest.SHA256 -> JwsAlgorithm.Signature.PS256
                Digest.SHA384 -> JwsAlgorithm.Signature.PS384
                Digest.SHA512 -> JwsAlgorithm.Signature.PS512
                else -> throw IllegalArgumentException("RSA-PSS with ${this.digest} is unsupported by JWS")
            }
        }
    }
}

fun DataIntegrityAlgorithm.toJwsAlgorithm(): KmmResult<JwsAlgorithm<*>> = catching {
    when (this) {
        is SignatureAlgorithm -> toJwsAlgorithm().getOrThrow()
        is MessageAuthenticationCode -> toJwsAlgorithm().getOrThrow()
        else -> throw IllegalArgumentException("Algorithm $this not supported by JWS")
    }
}

fun MessageAuthenticationCode.toJwsAlgorithm() = catching {
    when (this) {
        HMAC.SHA1 -> UNOFFICIAL_HS1
        HMAC.SHA256 -> JwsAlgorithm.MAC.HS256
        HMAC.SHA384 -> JwsAlgorithm.MAC.HS384
        HMAC.SHA512 -> JwsAlgorithm.MAC.HS512
    }
}

/** Tries to find a matching JWS algorithm. Note that JWS imposes curve restrictions on ECDSA based on the digest. */
fun SpecializedSignatureAlgorithm.toJwsAlgorithm() =
    this.algorithm.toJwsAlgorithm()


