@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package at.asitplus.signum.indispensable.cosef.algorithm

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.ec.ECCurve
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.SpecializedSymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * See [COSE Algorithm Registry](https://www.iana.org/assignments/cose/cose.xhtml)
 */
@Serializable(with = CoseAlgorithmSerializer::class)
interface CoseAlgorithm : Enumerable {

    @Serializable(with = CoseAlgorithmSerializer::class)
    interface Symmetric : CoseAlgorithm {
        companion object : Enumeration<Symmetric> {
            override val entries: Collection<Symmetric>
                get() = MAC.entries + SymmetricEncryption.entries
        }
    }

    val coseValue: Int

    @Deprecated("Use value instead", ReplaceWith("coseValue"))
    val value get() = coseValue

    @Serializable(with = CoseAlgorithmSerializer::class)
    open class DataIntegrity(
        override val coseValue: Int,
        override val algorithm: DataIntegrityAlgorithm,
        private val displayName: String = algorithm.toString(),
    ) : CoseAlgorithm, SpecializedDataIntegrityAlgorithm {
        override fun toString(): String = displayName

        companion object : Enumeration<DataIntegrity> {
            override val entries: Collection<DataIntegrity>
                get() = Signature.entries + MAC.entries
        }
    }

    @Serializable(with = CoseAlgorithmSerializer::class)
    open class SymmetricEncryption(
        override val coseValue: Int,
        override val algorithm: SymmetricEncryptionAlgorithm<*, *, *>,
        displayName: String = algorithm.toString(),
    ) : CoseAlgorithm.Symmetric, SpecializedSymmetricEncryptionAlgorithm {
        private val displayName = displayName

        override fun toString(): String = displayName

        companion object : Enumeration<SymmetricEncryption> {
            private val builtIns = linkedMapOf<Int, SymmetricEncryption>()

            override val entries: Collection<SymmetricEncryption>
                get() = builtIns.values

            fun <T : SymmetricEncryption> register(algorithm: T): T {
                builtIns.putIfAbsent(algorithm.coseValue, algorithm)
                return algorithm
            }

            val A128GCM = register(SymmetricEncryption(1, SymmetricEncryptionAlgorithm.AES_128_GCM, "A128GCM"))
            val A192GCM = register(SymmetricEncryption(2, SymmetricEncryptionAlgorithm.AES_192_GCM, "A192GCM"))
            val A256GCM = register(SymmetricEncryption(3, SymmetricEncryptionAlgorithm.AES_256_GCM, "A256GCM"))
            val ChaCha20Poly1305 =
                register(SymmetricEncryption(24, SymmetricEncryptionAlgorithm.ChaCha20Poly1305, "ChaCha20Poly1305"))
        }
    }

    @Serializable(with = CoseAlgorithmSerializer::class)
    open class Signature(
        value: Int,
        override val algorithm: SignatureAlgorithm,
        displayName: String = algorithm.toString(),
    ) : DataIntegrity(value, algorithm, displayName), SpecializedSignatureAlgorithm {
        companion object : Enumeration<Signature> {
            private val builtIns = linkedMapOf<Int, Signature>()

            override val entries: Collection<Signature>
                get() = builtIns.values

            fun <T : Signature> register(algorithm: T): T {
                builtIns.putIfAbsent(algorithm.coseValue, algorithm)
                return algorithm
            }

            val ES256 = register(Signature(-7, SignatureAlgorithm.ECDSA_SHA256, "ES256"))
            val ESP256 = register(Signature(-9, EcdsaSignatureAlgorithm(Digest.SHA256, requiredCurve = ECCurve.SECP_256_R_1), "ESP256"))
            val ES384 = register(Signature(-35, SignatureAlgorithm.ECDSA_SHA384, "ES384"))
            val ESP384 = register(Signature(-51, EcdsaSignatureAlgorithm(Digest.SHA384, requiredCurve = ECCurve.SECP_384_R_1), "ESP384"))
            val ES512 = register(Signature(-36, SignatureAlgorithm.ECDSA_SHA512, "ES512"))
            val ESP512 = register(Signature(-52, EcdsaSignatureAlgorithm(Digest.SHA512, requiredCurve = ECCurve.SECP_521_R_1), "ESP512"))
            val PS256 = register(Signature(-37, SignatureAlgorithm.RSA_SHA256_PSS, "PS256"))
            val PS384 = register(Signature(-38, SignatureAlgorithm.RSA_SHA384_PSS, "PS384"))
            val PS512 = register(Signature(-39, SignatureAlgorithm.RSA_SHA512_PSS, "PS512"))
            val RS256 = register(Signature(-257, SignatureAlgorithm.RSA_SHA256_PKCS1, "RS256"))
            val RS384 = register(Signature(-258, SignatureAlgorithm.RSA_SHA384_PKCS1, "RS384"))
            val RS512 = register(Signature(-259, SignatureAlgorithm.RSA_SHA512_PKCS1, "RS512"))
            val RS1 = register(Signature(-65535, RsaSignatureAlgorithm(Digest.SHA1, Pkcs1RsaSignaturePadding), "RS1"))
        }
    }

    @Serializable(with = CoseAlgorithmSerializer::class)
    open class MAC(
        value: Int,
        override val algorithm: MessageAuthenticationCode,
        displayName: String = algorithm.toString(),
    ) : DataIntegrity(value, algorithm, displayName), Symmetric, SpecializedMessageAuthenticationCode {
        val tagLength get() = algorithm.outputLength

        companion object : Enumeration<MAC> {
            private val builtIns = linkedMapOf<Int, MAC>()

            override val entries: Collection<MAC>
                get() = builtIns.values

            fun <T : MAC> register(algorithm: T): T {
                builtIns.putIfAbsent(algorithm.coseValue, algorithm)
                return algorithm
            }

            val HS256_64 = register(MAC(4, MessageAuthenticationCode.HMAC_SHA256.truncatedTo(64.bit), "HS256_64"))
            val HS256 = register(MAC(5, MessageAuthenticationCode.HMAC_SHA256, "HS256"))
            val HS384 = register(MAC(6, MessageAuthenticationCode.HMAC_SHA384, "HS384"))
            val HS512 = register(MAC(7, MessageAuthenticationCode.HMAC_SHA512, "HS512"))
            val UNOFFICIAL_HS1 = register(MAC(-2341169, MessageAuthenticationCode.HMAC_SHA1, "H1"))
        }
    }

    companion object : Enumeration<CoseAlgorithm> {
        override val entries: Collection<CoseAlgorithm>
            get() = DataIntegrity.entries + SymmetricEncryption.entries
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

    AlgorithmRegistry.registerSymmetricMapping(COSE_SYMMETRIC_NAMESPACE, SymmetricEncryptionAlgorithm.ChaCha20Poly1305, CoseAlgorithm.SymmetricEncryption.ChaCha20Poly1305)
    AlgorithmRegistry.registerSymmetricMapping(COSE_SYMMETRIC_NAMESPACE, SymmetricEncryptionAlgorithm.AES_128_GCM, CoseAlgorithm.SymmetricEncryption.A128GCM)
    AlgorithmRegistry.registerSymmetricMapping(COSE_SYMMETRIC_NAMESPACE, SymmetricEncryptionAlgorithm.AES_192_GCM, CoseAlgorithm.SymmetricEncryption.A192GCM)
    AlgorithmRegistry.registerSymmetricMapping(COSE_SYMMETRIC_NAMESPACE, SymmetricEncryptionAlgorithm.AES_256_GCM, CoseAlgorithm.SymmetricEncryption.A256GCM)
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

fun SpecializedSignatureAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.Signature> =
    this.algorithm.toCoseAlgorithm()

fun SpecializedDataIntegrityAlgorithm.toCoseAlgorithm(): KmmResult<CoseAlgorithm.DataIntegrity> =
    this.algorithm.toCoseAlgorithm()

fun SpecializedMessageAuthenticationCode.toCoseAlgorithm(): KmmResult<CoseAlgorithm.MAC> =
    this.algorithm.toCoseAlgorithm()
