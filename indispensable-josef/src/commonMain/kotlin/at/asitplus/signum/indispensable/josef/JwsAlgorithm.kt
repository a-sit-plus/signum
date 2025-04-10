@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.josef.JwsAlgorithm.MAC.UNOFFICIAL_HS1
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
sealed class JwsAlgorithm(override val identifier: String) :
    JsonWebAlgorithm, SpecializedDataIntegrityAlgorithm {

    @Serializable(with = JwsAlgorithmSerializer::class)
    sealed class Signature(identifier: String, override val algorithm: SignatureAlgorithm) :
        JwsAlgorithm(identifier),
        SpecializedSignatureAlgorithm {

        sealed class EC(identifier: String, algorithm: SignatureAlgorithm) : Signature(identifier, algorithm) {
            @Serializable(with = JwsAlgorithmSerializer::class)
            data object ES256 : EC("ES256", SignatureAlgorithm.ECDSAwithSHA256)

            @Serializable(with = JwsAlgorithmSerializer::class)
            data object ES384 : EC("ES384", SignatureAlgorithm.ECDSAwithSHA384)

            @Serializable(with = JwsAlgorithmSerializer::class)
            data object ES512 : EC("ES512", SignatureAlgorithm.ECDSAwithSHA512)

            /** The curve to create signatures on.
             * This is fixed by RFC7518, as opposed to X.509 where other combinations are possible. */
            val ecCurve: ECCurve
                get() = when (this) {
                    ES256 -> ECCurve.SECP_256_R_1
                    ES384 -> ECCurve.SECP_384_R_1
                    ES512 -> ECCurve.SECP_521_R_1
                }

            companion object {
                val entries: Collection<Signature.EC> by lazy {
                    listOf(
                        ES256,
                        ES384,
                        ES512,
                    )
                }
            }
        }

        sealed class RSA(identifier: String, algorithm: SignatureAlgorithm) : Signature(identifier, algorithm) {

            @Serializable(with = JwsAlgorithmSerializer::class)
            data object PS256 : RSA("PS256", SignatureAlgorithm.RSAwithSHA256andPSSPadding)

            @Serializable(with = JwsAlgorithmSerializer::class)
            data object PS384 : RSA("PS384", SignatureAlgorithm.RSAwithSHA384andPSSPadding)

            @Serializable(with = JwsAlgorithmSerializer::class)
            data object PS512 : RSA("PS512", SignatureAlgorithm.RSAwithSHA512andPSSPadding)


            @Serializable(with = JwsAlgorithmSerializer::class)
            data object RS256 : RSA("RS256", SignatureAlgorithm.RSAwithSHA256andPKCS1Padding)

            @Serializable(with = JwsAlgorithmSerializer::class)
            data object RS384 : RSA("RS384", SignatureAlgorithm.RSAwithSHA384andPKCS1Padding)

            @Serializable(with = JwsAlgorithmSerializer::class)
            data object RS512 : RSA("RS512", SignatureAlgorithm.RSAwithSHA512andPKCS1Padding)

            /** The one exception, which is not a valid JWS algorithm identifier */

            @Serializable(with = JwsAlgorithmSerializer::class)
            data object NON_JWS_SHA1_WITH_RSA : RSA("RS1", SignatureAlgorithm.RSA(Digest.SHA1, RSAPadding.PKCS1))
            companion object {
                val entries: Collection<Signature.RSA> by lazy {
                    listOf(
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

        }


        open val digest: Digest?
            get() = when (algorithm) {
                is SignatureAlgorithm.ECDSA -> (this as SignatureAlgorithm.ECDSA).digest
                is SignatureAlgorithm.RSA -> (this as SignatureAlgorithm.RSA).digest
            }

        companion object {
            val entries: Collection<Signature> by lazy { EC.entries + RSA.entries }
            //convenience
            val ES256 = EC.ES256
            val ES384 = EC.ES384
            val ES512 = EC.ES512
            val RS256 = RSA.RS256
            val RS384 = RSA.RS384
            val RS512 = RSA.RS512
            val PS256 = RSA.PS256
            val PS384 = RSA.PS384
            val PS512 = RSA.PS512
            val NON_JWS_SHA1_WITH_RSA = RSA.NON_JWS_SHA1_WITH_RSA
        }

    }

    @Serializable(with = JwsAlgorithmSerializer::class)
    sealed class MAC(identifier: String, override val algorithm: MessageAuthenticationCode) :
        JwsAlgorithm(identifier) {

        @Serializable(with = JwsAlgorithmSerializer::class)
        data object HS256 : MAC("HS256", HMAC.SHA256)

        @Serializable(with = JwsAlgorithmSerializer::class)
        data object HS384 : MAC("HS384", HMAC.SHA384)

        @Serializable(with = JwsAlgorithmSerializer::class)
        data object HS512 : MAC("HS512", HMAC.SHA512)

        @Serializable(with = JwsAlgorithmSerializer::class)
        data object UNOFFICIAL_HS1 : MAC("H1", HMAC.SHA1)

        companion object {
            val entries: Collection<MAC> by lazy {
                listOf(
                    HS256,
                    HS384,
                    HS512,
                    UNOFFICIAL_HS1,
                )
            }
        }
    }

    companion object {
        //Why can't these entries be accessed right away and directly assigning always result in a nullpointer?
        //why does it need lazy?
        val entries: Collection<JwsAlgorithm> by lazy { Signature.entries + MAC.entries }
    }
}

object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsAlgorithm) =
        JwaSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JwsAlgorithm {
        val decoded = decoder.decodeString()
        return JwsAlgorithm.entries.first { it.identifier == decoded }
    }
}

/** Tries to find a matching JWS algorithm. Note that JWS imposes curve restrictions on ECDSA based on the digest. */
fun SignatureAlgorithm.toJwsAlgorithm(): KmmResult<JwsAlgorithm> = catching {
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

fun DataIntegrityAlgorithm.toJwsAlgorithm(): KmmResult<JwsAlgorithm> = catching {
    when (this) {
        is SignatureAlgorithm -> toJwsAlgorithm().getOrThrow()
        is MessageAuthenticationCode -> toJwsAlgorithm().getOrThrow()
    }
}

fun MessageAuthenticationCode.toJwsAlgorithm(): KmmResult<JwsAlgorithm> = catching {
    when (this) {
        HMAC.SHA1 -> UNOFFICIAL_HS1
        HMAC.SHA256 -> JwsAlgorithm.MAC.HS256
        HMAC.SHA384 -> JwsAlgorithm.MAC.HS384
        HMAC.SHA512 -> JwsAlgorithm.MAC.HS512
        else -> throw UnsupportedCryptoException("$this has no JWS equivalent")
    }
}

/** Tries to find a matching JWS algorithm*/
fun SpecializedDataIntegrityAlgorithm.toJwsAlgorithm() =
    this.algorithm.toJwsAlgorithm()

/** Tries to find a matching JWS algorithm.*/
fun SpecializedMessageAuthenticationCode.toJwsAlgorithm() =
    this.algorithm.toJwsAlgorithm()

/** Tries to find a matching JWS algorithm.*/
fun SpecializedSignatureAlgorithm.toJwsAlgorithm() =
    this.algorithm.toJwsAlgorithm()