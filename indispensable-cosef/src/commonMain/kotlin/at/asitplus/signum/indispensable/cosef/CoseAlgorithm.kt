@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.SpecializedSymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
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
sealed interface CoseAlgorithm : Enumerable {

    @Serializable(with = CoseAlgorithmSerializer::class)
    sealed interface Symmetric : CoseAlgorithm {
        companion object : Enumeration<Symmetric> {
            override val entries: Collection<Symmetric> = MAC.entries + SymmetricEncryption.entries
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
        companion object : Enumeration<DataIntegrity> {
            override val entries: Collection<DataIntegrity> by lazy { Signature.entries + MAC.entries }
        }
    }

    @Serializable(with = CoseAlgorithmSerializer::class)
    sealed class SymmetricEncryption(
        override val coseValue: Int,
        override val algorithm: SymmetricEncryptionAlgorithm<*, *, *>
    ) :
        CoseAlgorithm.Symmetric, SpecializedSymmetricEncryptionAlgorithm {


        @Serializable(with = CoseAlgorithmSerializer::class)
        data object A128GCM : SymmetricEncryption(1, SymmetricEncryptionAlgorithm.AES_128.GCM)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object A192GCM : SymmetricEncryption(2, SymmetricEncryptionAlgorithm.AES_192.GCM)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object A256GCM : SymmetricEncryption(3, SymmetricEncryptionAlgorithm.AES_256.GCM)


        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ChaCha20Poly1305 : SymmetricEncryption(24, SymmetricEncryptionAlgorithm.ChaCha20Poly1305)

        companion object : Enumeration<SymmetricEncryption> {
            override val entries: Collection<SymmetricEncryption> by lazy {
                setOf(
                    A128GCM,
                    A192GCM,
                    A256GCM,
                    ChaCha20Poly1305
                )
            }
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
        data object ESP256 :
            Signature(-9, SignatureAlgorithm.ECDSA(Digest.SHA256, requiredCurve = ECCurve.SECP_256_R_1))

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ES384 : Signature(-35, SignatureAlgorithm.ECDSAwithSHA384)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ESP384 :
            Signature(-51, SignatureAlgorithm.ECDSA(Digest.SHA384, requiredCurve = ECCurve.SECP_384_R_1))

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ES512 : Signature(-36, SignatureAlgorithm.ECDSAwithSHA512)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ESP512 :
            Signature(-52, SignatureAlgorithm.ECDSA(Digest.SHA512, requiredCurve = ECCurve.SECP_521_R_1))

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

        companion object : Enumeration<Signature> {
            override val entries: Collection<Signature> by lazy {
                setOf(
                    ESP256,
                    ES256,
                    ESP384,
                    ES384,
                    ESP512,
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

        companion object : Enumeration<MAC> {
            override val entries: Collection<MAC> by lazy {
                setOf(
                    HS256,
                    HS256_64,
                    HS384,
                    HS512,
                    UNOFFICIAL_HS1,
                )
            }
        }
    }

    sealed class HPKE(
        override val coseValue: Int, val kem_id: Int, val kdf_id: Int, val aead_id: Int)
        : CoseAlgorithm, Enumerable
    {
        companion object : Enumeration<HPKE> {
            override val entries: Collection<HPKE> by lazy {
                setOf(HPKE_0, HPKE_1, HPKE_2, HPKE_3, HPKE_4, HPKE_5, HPKE_6, HPKE_7)
            }
        }
    }

    /** COSE HPKE Integrated Encryption using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD */
    data object HPKE_0 : HPKE(35, 0x10, 0x1, 0x1)

    /** COSE HPKE Integrated Encryption using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD */
    data object HPKE_1 : HPKE(37, 0x11, 0x2, 0x2)

    /** COSE HPKE Integrated Encryption using DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD */
    data object HPKE_2 : HPKE(39, 0x12, 0x3, 0x2)

    /** COSE HPKE Integrated Encryption using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD */
    data object HPKE_3 : HPKE(41, 0x20, 0x1, 0x1)

    /** COSE HPKE Integrated Encryption using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD */
    data object HPKE_4 : HPKE(42, 0x20, 0x1, 0x3)

    /** COSE HPKE Integrated Encryption using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD */
    data object HPKE_5 : HPKE(43, 0x21, 0x3, 0x2)

    /** COSE HPKE Integrated Encryption using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD */
    data object HPKE_6 : HPKE(44, 0x21, 0x3, 0x3)

    /** COSE HPKE Integrated Encryption using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD */
    data object HPKE_7 : HPKE(45, 0x10, 0x1, 0x2)

    sealed class HPKE_KE(
        override val coseValue: Int, val kem_id: Int, val kdf_id: Int, val aead_id: Int)
        : CoseAlgorithm, Enumerable
    {
        companion object : Enumeration<HPKE_KE> {
            override val entries: Collection<HPKE_KE> by lazy {
                setOf(HPKE_0_KE, HPKE_1_KE, HPKE_2_KE, HPKE_3_KE, HPKE_4_KE, HPKE_5_KE, HPKE_6_KE, HPKE_7_KE)
            }
        }
    }

    /** COSE HPKE Key Encryption using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD */
    data object HPKE_0_KE : HPKE_KE(46, 0x10, 0x1, 0x1)

    /** COSE HPKE Key Encryption using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD */
    data object HPKE_1_KE : HPKE_KE(47, 0x11, 0x2, 0x2)

    /** COSE HPKE Key Encryption using DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD */
    data object HPKE_2_KE : HPKE_KE(48, 0x12, 0x3, 0x2)

    /** COSE HPKE Key Encryption using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD */
    data object HPKE_3_KE : HPKE_KE(49, 0x20, 0x1, 0x1)

    /** COSE HPKE Key Encryption using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD */
    data object HPKE_4_KE : HPKE_KE(50, 0x20, 0x1, 0x3)

    /** COSE HPKE Key Encryption using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD */
    data object HPKE_5_KE : HPKE_KE(51, 0x21, 0x3, 0x2)

    /** COSE HPKE Key Encryption using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD */
    data object HPKE_6_KE : HPKE_KE(52, 0x21, 0x3, 0x3)

    /** COSE HPKE Key Encryption using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD */
    data object HPKE_7_KE : HPKE_KE(53, 0x10, 0x1, 0x2)

    companion object : Enumeration<CoseAlgorithm> {
        override val entries: Collection<CoseAlgorithm> by lazy {
            DataIntegrity.entries + SymmetricEncryption.entries + HPKE.entries + HPKE_KE.entries
        }
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
            Digest.SHA256 -> when (this.requiredCurve) {
                ECCurve.SECP_256_R_1 -> CoseAlgorithm.Signature.ESP256
                null -> CoseAlgorithm.Signature.ES256
                else -> throw UnsupportedCryptoException("ECDSA with ${this.digest} and $requiredCurve is unsupported by COSE")
            }

            Digest.SHA384 -> when (this.requiredCurve) {
                ECCurve.SECP_384_R_1 -> CoseAlgorithm.Signature.ESP384
                null -> CoseAlgorithm.Signature.ES384
                else -> throw UnsupportedCryptoException("ECDSA with ${this.digest} and $requiredCurve is unsupported by COSE")
            }

            Digest.SHA512 -> when (this.requiredCurve) {
                ECCurve.SECP_521_R_1 -> CoseAlgorithm.Signature.ESP512
                null -> CoseAlgorithm.Signature.ES512
                else -> throw UnsupportedCryptoException("ECDSA with ${this.digest} and $requiredCurve is unsupported by COSE")
            }

            else -> throw UnsupportedCryptoException("ECDSA with ${this.digest} is unsupported by COSE")
        }

        is SignatureAlgorithm.RSA -> when (this.padding) {
            RSAPadding.PKCS1 -> when (this.digest) {
                Digest.SHA1 -> CoseAlgorithm.Signature.RS1
                Digest.SHA256 -> CoseAlgorithm.Signature.RS256
                Digest.SHA384 -> CoseAlgorithm.Signature.RS384
                Digest.SHA512 -> CoseAlgorithm.Signature.RS512
            }

            is RSAPadding.PSS -> when (this.digest) {
                Digest.SHA256 -> CoseAlgorithm.Signature.PS256
                Digest.SHA384 -> CoseAlgorithm.Signature.PS384
                Digest.SHA512 -> CoseAlgorithm.Signature.PS512
                else -> throw UnsupportedCryptoException("RSA-PSS with ${this.digest} is unsupported by COSE")
            }
        }
    }
}

fun DataIntegrityAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.DataIntegrity> =
    when (this) {
        is SignatureAlgorithm -> toCoseAlgorithm()
        is MessageAuthenticationCode -> toCoseAlgorithm()
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
