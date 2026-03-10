@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.AesGcmAlgorithm
import at.asitplus.signum.indispensable.symmetric.SpecializedSymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.SerializationException

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
        data object A128GCM : SymmetricEncryption(1, SymmetricEncryptionAlgorithm.AES_128_GCM)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object A192GCM : SymmetricEncryption(2, SymmetricEncryptionAlgorithm.AES_192_GCM)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object A256GCM : SymmetricEncryption(3, SymmetricEncryptionAlgorithm.AES_256_GCM)


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
        data object ES256 : Signature(-7, SignatureAlgorithm.ECDSA_SHA256)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ESP256 :
            Signature(-9, EcdsaSignatureAlgorithm(Digest.SHA256, requiredCurve = ECCurve.SECP_256_R_1))

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ES384 : Signature(-35, SignatureAlgorithm.ECDSA_SHA384)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ESP384 :
            Signature(-51, EcdsaSignatureAlgorithm(Digest.SHA384, requiredCurve = ECCurve.SECP_384_R_1))

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ES512 : Signature(-36, SignatureAlgorithm.ECDSA_SHA512)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object ESP512 :
            Signature(-52, EcdsaSignatureAlgorithm(Digest.SHA512, requiredCurve = ECCurve.SECP_521_R_1))

        // RSASSA-PSS with SHA-size
        @Serializable(with = CoseAlgorithmSerializer::class)
        data object PS256 : Signature(-37, SignatureAlgorithm.RSA_SHA256_PSS)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object PS384 : Signature(-38, SignatureAlgorithm.RSA_SHA384_PSS)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object PS512 : Signature(-39, SignatureAlgorithm.RSA_SHA512_PSS)

        // RSASSA-PKCS1-v1_5 with SHA-size
        @Serializable(with = CoseAlgorithmSerializer::class)
        data object RS256 : Signature(-257, SignatureAlgorithm.RSA_SHA256_PKCS1)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object RS384 : Signature(-258, SignatureAlgorithm.RSA_SHA384_PKCS1)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object RS512 : Signature(-259, SignatureAlgorithm.RSA_SHA512_PKCS1)

        // RSASSA-PKCS1-v1_5 using SHA-1
        @Serializable(with = CoseAlgorithmSerializer::class)
        data object RS1 : Signature(-65535, RsaSignatureAlgorithm(Digest.SHA1, Pkcs1RsaSignaturePadding))

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
        data object HS256_64 : MAC(4, MessageAuthenticationCode.HMAC_SHA256.truncatedTo(64.bit))

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object HS256 : MAC(5, MessageAuthenticationCode.HMAC_SHA256)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object HS384 : MAC(6, MessageAuthenticationCode.HMAC_SHA384)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object HS512 : MAC(7, MessageAuthenticationCode.HMAC_SHA512)

        @Serializable(with = CoseAlgorithmSerializer::class)
        data object UNOFFICIAL_HS1 : MAC(-2341169 /*random inside private use range*/, MessageAuthenticationCode.HMAC_SHA1)

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

    companion object : Enumeration<CoseAlgorithm> {
        override val entries: Collection<CoseAlgorithm> by lazy { DataIntegrity.entries + SymmetricEncryption.entries }
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
        return CoseAlgorithm.entries.firstOrNull { it.coseValue == decoded }
            ?: throw SerializationException("Unsupported COSE algorithm value $decoded")
    }

}

private const val COSE_SIGNATURE_NAMESPACE = "cose.signature"
private const val COSE_MAC_NAMESPACE = "cose.mac"
private const val COSE_SYMMETRIC_NAMESPACE = "cose.symmetric"

private val coseBuiltInMappings = run {
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.ECDSA_SHA256, CoseAlgorithm.Signature.ES256)
    AlgorithmRegistry.registerSignatureMapping(
        COSE_SIGNATURE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA256, ECCurve.SECP_256_R_1, null),
        CoseAlgorithm.Signature.ESP256
    )
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.ECDSA_SHA384, CoseAlgorithm.Signature.ES384)
    AlgorithmRegistry.registerSignatureMapping(
        COSE_SIGNATURE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA384, ECCurve.SECP_384_R_1, null),
        CoseAlgorithm.Signature.ESP384
    )
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.ECDSA_SHA512, CoseAlgorithm.Signature.ES512)
    AlgorithmRegistry.registerSignatureMapping(
        COSE_SIGNATURE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA512, ECCurve.SECP_521_R_1, null),
        CoseAlgorithm.Signature.ESP512
    )
    AlgorithmRegistry.registerSignatureMapping(
        COSE_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA1, null, RsaSignaturePadding.PKCS1),
        CoseAlgorithm.Signature.RS1
    )
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.RSA_SHA256_PKCS1, CoseAlgorithm.Signature.RS256)
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.RSA_SHA384_PKCS1, CoseAlgorithm.Signature.RS384)
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.RSA_SHA512_PKCS1, CoseAlgorithm.Signature.RS512)
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.RSA_SHA256_PSS, CoseAlgorithm.Signature.PS256)
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.RSA_SHA384_PSS, CoseAlgorithm.Signature.PS384)
    AlgorithmRegistry.registerSignatureMapping(COSE_SIGNATURE_NAMESPACE, SignatureAlgorithm.RSA_SHA512_PSS, CoseAlgorithm.Signature.PS512)

    AlgorithmRegistry.registerMacMapping(COSE_MAC_NAMESPACE, MessageAuthenticationCode.HMAC_SHA1, CoseAlgorithm.MAC.UNOFFICIAL_HS1)
    AlgorithmRegistry.registerMacMapping(COSE_MAC_NAMESPACE, MessageAuthenticationCode.HMAC_SHA256, CoseAlgorithm.MAC.HS256)
    AlgorithmRegistry.registerMacMapping(COSE_MAC_NAMESPACE, MessageAuthenticationCode.HMAC_SHA384, CoseAlgorithm.MAC.HS384)
    AlgorithmRegistry.registerMacMapping(COSE_MAC_NAMESPACE, MessageAuthenticationCode.HMAC_SHA512, CoseAlgorithm.MAC.HS512)
    AlgorithmRegistry.registerMacMapping(COSE_MAC_NAMESPACE, MacMappingKey(Digest.SHA256, 64.bit), CoseAlgorithm.MAC.HS256_64)

    AlgorithmRegistry.registerSymmetricMapping(
        COSE_SYMMETRIC_NAMESPACE,
        SymmetricMappingKey(ChaCha20Poly1305SymmetricMappingKind, SymmetricEncryptionAlgorithm.ChaCha20Poly1305.keySize),
        CoseAlgorithm.SymmetricEncryption.ChaCha20Poly1305
    )
    AlgorithmRegistry.registerSymmetricMapping(COSE_SYMMETRIC_NAMESPACE, SymmetricMappingKey(AesGcmSymmetricMappingKind, 128.bit), CoseAlgorithm.SymmetricEncryption.A128GCM)
    AlgorithmRegistry.registerSymmetricMapping(COSE_SYMMETRIC_NAMESPACE, SymmetricMappingKey(AesGcmSymmetricMappingKind, 192.bit), CoseAlgorithm.SymmetricEncryption.A192GCM)
    AlgorithmRegistry.registerSymmetricMapping(COSE_SYMMETRIC_NAMESPACE, SymmetricMappingKey(AesGcmSymmetricMappingKind, 256.bit), CoseAlgorithm.SymmetricEncryption.A256GCM)
}

/** Tries to find a matching COSE algorithm. Note that COSE imposes curve restrictions on ECDSA based on the digest. */
fun SignatureAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.Signature> = catching {
    coseBuiltInMappings
    AlgorithmRegistry.findSignatureMapping<CoseAlgorithm.Signature>(COSE_SIGNATURE_NAMESPACE, this)
        ?: throw UnsupportedCryptoException("$this has no COSE signature mapping")
}

fun DataIntegrityAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.DataIntegrity> =
    when (this) {
        is SignatureAlgorithm -> toCoseAlgorithm()
        is MessageAuthenticationCode -> toCoseAlgorithm()
        else -> KmmResult.failure(UnsupportedCryptoException("$this has no COSE data integrity mapping"))
    }

/** Tries to find a matching COSE algorithm. Note that [CoseAlgorithm.MAC.HS256_64] cannot be mapped automatically. */
fun MessageAuthenticationCode.toCoseAlgorithm(): KmmResult<CoseAlgorithm.MAC> = catching {
    coseBuiltInMappings
    AlgorithmRegistry.findMacMapping<CoseAlgorithm.MAC>(COSE_MAC_NAMESPACE, this)
        ?: throw UnsupportedCryptoException("$this has no COSE MAC mapping")
}

/** Tries to find a matching COSE algorithm. Note that only AES-GCM and ChaCha/Poly are supported. */
fun SymmetricEncryptionAlgorithm<*, *, *>.toCoseAlgorithm(): KmmResult<CoseAlgorithm.SymmetricEncryption> = catching {
    coseBuiltInMappings
    AlgorithmRegistry.findSymmetricMapping<CoseAlgorithm.SymmetricEncryption>(COSE_SYMMETRIC_NAMESPACE, this)
        ?: throw UnsupportedCryptoException("$this has no COSE algorithm mapping")
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
