@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.MessageAuthenticationCode
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.UnsupportedCryptoException
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * See [COSE Algorithm Registry](https://www.iana.org/assignments/cose/cose.xhtml)
 */
@Serializable(with = CoseAlgorithmSerializer::class)
sealed interface CoseAlgorithm {

    sealed interface Symmetric : CoseAlgorithm {
        companion object {
            val entries: Collection<Symmetric> = MAC.entries + SymmetricEncryption.entries
        }
    }

    /**
     * See [COSE Algorithm Registry](https://www.iana.org/assignments/cose/cose.xhtml)
     */
    val coseValue: Int

    @Deprecated("Use value instead", ReplaceWith("coseValue"))
    val value get() = coseValue

    @Serializable(with = CoseAlgorithmSerializer::class)
    sealed class DataIntegrity(override val coseValue: Int) : CoseAlgorithm, SpecializedDataIntegrityAlgorithm {
        companion object {
            val entries: Collection<DataIntegrity> by lazy { Signature.entries + MAC.entries }
        }
    }

    @Serializable(with = CoseAlgorithmSerializer::class)
    sealed class SymmetricEncryption(override val coseValue: Int, val algorithm: SymmetricEncryptionAlgorithm<*, *, *>) :
        CoseAlgorithm.Symmetric {


        @Serializable(with = CoseAlgorithmSerializer::class)
        data object A128GCM : SymmetricEncryption(1, SymmetricEncryptionAlgorithm.AES_128.GCM)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object A192GCM : SymmetricEncryption(2, SymmetricEncryptionAlgorithm.AES_192.GCM)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object A256GCM : SymmetricEncryption(3, SymmetricEncryptionAlgorithm.AES_256.GCM)


        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ChaCha20Poly1305 : SymmetricEncryption(24, SymmetricEncryptionAlgorithm.ChaCha20Poly1305)

        companion object {
            val entries: Collection<SymmetricEncryption> by lazy { listOf(A128GCM, A192GCM, A256GCM, ChaCha20Poly1305) }
        }
    }


    @Serializable(with = CoseAlgorithmSerializer::class)
    sealed class Signature(value: Int, override val algorithm: SignatureAlgorithm) :
        DataIntegrity(value),
        SpecializedSignatureAlgorithm {

        // ECDSA with SHA-size
        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ES256 : Signature(-7, SignatureAlgorithm.ECDSAwithSHA256)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ES384 : Signature(-35, SignatureAlgorithm.ECDSAwithSHA384)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ES512 : Signature(-36, SignatureAlgorithm.ECDSAwithSHA512)

        // RSASSA-PSS with SHA-size
        @Serializable(with = CoseAlgorithmSerializer::class)
        data object PS256 : Signature(-37, SignatureAlgorithm.RSAwithSHA256andPSSPadding)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object PS384 : Signature(-38, SignatureAlgorithm.RSAwithSHA384andPSSPadding)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object PS512 : Signature(-39, SignatureAlgorithm.RSAwithSHA512andPSSPadding)

        // RSASSA-PKCS1-v1_5 with SHA-size
        @Serializable(with = CoseAlgorithmSerializer::class)
        data object RS256 : Signature(-257, SignatureAlgorithm.RSAwithSHA256andPKCS1Padding)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object RS384 : Signature(-258, SignatureAlgorithm.RSAwithSHA384andPKCS1Padding)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object RS512 : Signature(-259, SignatureAlgorithm.RSAwithSHA512andPKCS1Padding)

        // RSASSA-PKCS1-v1_5 using SHA-1
        @Serializable(with = CoseAlgorithmSerializer::class)
        data object RS1 : Signature(-65535, SignatureAlgorithm.RSA(Digest.SHA1, RSAPadding.PKCS1))

        companion object {
            val entries: Collection<Signature> by lazy {
                listOf(
                    ES256,
                    ES384,
                    ES512,
                    PS256,
                    PS384,
                    PS512,
                    RS256,
                    RS384,
                    RS512,
                    RS1,
                )
            }
        }

    }


    @Serializable(with = CoseAlgorithmSerializer::class)
    sealed class MAC(
        value: Int,
        override val algorithm: MessageAuthenticationCode
    ) :
        DataIntegrity(value), Symmetric, SpecializedMessageAuthenticationCode {

        val tagLength get() = algorithm.outputLength

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object HS256_64 : MAC(4, HMAC.SHA256.truncatedTo(64.bit))

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object HS256 : MAC(5, HMAC.SHA256)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object HS384 : MAC(6, HMAC.SHA384)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object HS512 : MAC(7, HMAC.SHA512)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object UNOFFICIAL_HS1 : MAC(-2341169 /*random inside private use range*/, HMAC.SHA1)

        companion object {
            val entries: Collection<MAC> by lazy {
                listOf(
                    HS256,
                    HS256_64,
                    HS384,
                    HS512,
                    UNOFFICIAL_HS1,
                )
            }
        }
    }

    companion object {
        val entries: Collection<CoseAlgorithm> by lazy { DataIntegrity.entries + SymmetricEncryption.entries }
    }

}

object CoseAlgorithmSerializer : KSerializer<CoseAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseAlgorithmSerializer", PrimitiveKind.INT)

    override fun serialize(encoder: Encoder, value: CoseAlgorithm) {
        value.let { encoder.encodeInt(it.coseValue) }
    }

    override fun deserialize(decoder: Decoder): CoseAlgorithm {
        val decoded = decoder.decodeInt()
        return CoseAlgorithm.entries.first { it.coseValue == decoded }
    }

}

/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun SignatureAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.Signature> = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA -> when (this.digest) {
            Digest.SHA256 -> CoseAlgorithm.Signature.ES256
            Digest.SHA384 -> CoseAlgorithm.Signature.ES384
            Digest.SHA512 -> CoseAlgorithm.Signature.ES512
            else -> throw UnsupportedCryptoException("ECDSA with ${this.digest} is unsupported by COSE")
        }

        is SignatureAlgorithm.RSA -> when (this.padding) {
            RSAPadding.PKCS1 -> when (this.digest) {
                Digest.SHA1 -> CoseAlgorithm.Signature.RS1
                Digest.SHA256 -> CoseAlgorithm.Signature.RS256
                Digest.SHA384 -> CoseAlgorithm.Signature.RS384
                Digest.SHA512 -> CoseAlgorithm.Signature.RS512
            }

            RSAPadding.PSS -> when (this.digest) {
                Digest.SHA256 -> CoseAlgorithm.Signature.PS256
                Digest.SHA384 -> CoseAlgorithm.Signature.PS384
                Digest.SHA512 -> CoseAlgorithm.Signature.PS512
                else -> throw UnsupportedCryptoException("RSA-PSS with ${this.digest} is unsupported by COSE")
            }
        }
    }
}

fun DataIntegrityAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.DataIntegrity> = catching {
     when (this) {
        is SignatureAlgorithm -> toCoseAlgorithm().getOrThrow()
        is MessageAuthenticationCode -> toCoseAlgorithm().getOrThrow()
    }
}

/** Tries to find a matching COSE algorithm. Note that [CoseAlgorithm.MAC.HS256_64] cannot be mapped automatically. */
fun MessageAuthenticationCode.toCoseAlgorithm(): KmmResult<CoseAlgorithm.MAC> = catching {
    when (this) {
        HMAC.SHA1 -> CoseAlgorithm.MAC.UNOFFICIAL_HS1
        HMAC.SHA256 -> CoseAlgorithm.MAC.HS256
        HMAC.SHA384 -> CoseAlgorithm.MAC.HS384
        HMAC.SHA512 -> CoseAlgorithm.MAC.HS512
        is MessageAuthenticationCode.Truncated -> when {
            (inner == HMAC.SHA256) && (outputLength == 64.bit) -> CoseAlgorithm.MAC.HS256_64
            else -> throw UnsupportedCryptoException("$this has no COSE equivalent")
        }
    }
}

/** Tries to find a matching COSE algorithm. Note that only AES-GCM and ChaCha/Poly are supported. */
fun SymmetricEncryptionAlgorithm<*, *, *>.toCoseAlgorithm(): KmmResult<CoseAlgorithm.SymmetricEncryption> = catching {
    when (this) {
        SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> CoseAlgorithm.SymmetricEncryption.ChaCha20Poly1305
        SymmetricEncryptionAlgorithm.AES_128.GCM -> CoseAlgorithm.SymmetricEncryption.A128GCM
        SymmetricEncryptionAlgorithm.AES_192.GCM -> CoseAlgorithm.SymmetricEncryption.A192GCM
        SymmetricEncryptionAlgorithm.AES_256.GCM -> CoseAlgorithm.SymmetricEncryption.A256GCM
        else -> throw UnsupportedCryptoException("$this has no COSE algorithm mapping")
    }
}

/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun SpecializedSignatureAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.Signature> =
    this.algorithm.toCoseAlgorithm()
/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun SpecializedDataIntegrityAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.DataIntegrity> =
    this.algorithm.toCoseAlgorithm()
/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun SpecializedMessageAuthenticationCode.toCoseAlgorithm(): KmmResult<CoseAlgorithm.MAC> =
    this.algorithm.toCoseAlgorithm()