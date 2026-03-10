package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asn1.toAsn1Integer
import at.asitplus.signum.indispensable.asn1.toJavaBigInteger
import at.asitplus.signum.indispensable.asymmetric.*
import at.asitplus.signum.indispensable.symmetric.AesCbcBase
import at.asitplus.signum.indispensable.symmetric.AesEcbAlgorithm
import at.asitplus.signum.indispensable.symmetric.AesGcmAlgorithm
import at.asitplus.signum.indispensable.symmetric.AesWrapAlgorithm
import at.asitplus.signum.indispensable.symmetric.ChaCha20Poly1305Algorithm
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.internals.isAndroid
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerializationException
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.security.KeyFactory
import java.security.PrivateKey as JcaPrivateKey
import java.security.PublicKey as JcaPublicKey
import java.security.Signature as JcaSignature
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


private val certificateFactoryMutex = Mutex()
private val certFactory = CertificateFactory.getInstance("X.509")

val Digest.jcaPSSParams
    get() = when (this) {
        Digest.SHA1 -> PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1)
        Digest.SHA256 -> PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
        Digest.SHA384 -> PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
        Digest.SHA512 -> PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
    }

internal fun sigGetInstance(alg: String, provider: String?): JcaSignature =
    when (provider) {
        null -> JcaSignature.getInstance(alg)
        else -> JcaSignature.getInstance(alg, provider)
    }

private fun interface JcaSignatureFactory {
    fun create(provider: String?): JcaSignature
}

private data class JcaCipherConfiguration(
    val transformation: String,
    val parameterSpec: AlgorithmParameterSpec?,
)

private const val JCA_SIGNATURE_NAMESPACE = "jca.signature"
private const val JCA_SIGNATURE_PREHASHED_NAMESPACE = "jca.signature.prehashed"
private const val JCA_ASYMMETRIC_CIPHER_NAMESPACE = "jca.cipher.asymmetric"

@OptIn(HazardousMaterials::class)
private val jcaBuiltInMappings = run {
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA1, null, null),
        JcaSignatureFactory { provider -> sigGetInstance("SHA1withECDSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA256, null, null),
        JcaSignatureFactory { provider -> sigGetInstance("SHA256withECDSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA384, null, null),
        JcaSignatureFactory { provider -> sigGetInstance("SHA384withECDSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA512, null, null),
        JcaSignatureFactory { provider -> sigGetInstance("SHA512withECDSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA1, null, RsaSignaturePadding.PKCS1),
        JcaSignatureFactory { provider -> sigGetInstance("SHA1withRSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA256, null, RsaSignaturePadding.PKCS1),
        JcaSignatureFactory { provider -> sigGetInstance("SHA256withRSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA384, null, RsaSignaturePadding.PKCS1),
        JcaSignatureFactory { provider -> sigGetInstance("SHA384withRSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA512, null, RsaSignaturePadding.PKCS1),
        JcaSignatureFactory { provider -> sigGetInstance("SHA512withRSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA256, null, RsaSignaturePadding.PSS),
        JcaSignatureFactory { provider -> sigGetInstance("RSASSA-PSS", provider).also { it.setParameter(Digest.SHA256.jcaPSSParams) } }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA384, null, RsaSignaturePadding.PSS),
        JcaSignatureFactory { provider -> sigGetInstance("RSASSA-PSS", provider).also { it.setParameter(Digest.SHA384.jcaPSSParams) } }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA512, null, RsaSignaturePadding.PSS),
        JcaSignatureFactory { provider -> sigGetInstance("RSASSA-PSS", provider).also { it.setParameter(Digest.SHA512.jcaPSSParams) } }
    )

    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA1, null, null),
        JcaSignatureFactory { provider -> sigGetInstance("NONEwithECDSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA256, null, null),
        JcaSignatureFactory { provider -> sigGetInstance("NONEwithECDSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA384, null, null),
        JcaSignatureFactory { provider -> sigGetInstance("NONEwithECDSA", provider) }
    )
    AlgorithmRegistry.registerSignatureMapping(
        JCA_SIGNATURE_PREHASHED_NAMESPACE,
        SignatureMappingKey(EcdsaSignatureMappingFamily, Digest.SHA512, null, null),
        JcaSignatureFactory { provider -> sigGetInstance("NONEwithECDSA", provider) }
    )

    AlgorithmRegistry.registerAsymmetricMapping(
        JCA_ASYMMETRIC_CIPHER_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.OAEP_SHA1),
        JcaCipherConfiguration(
            "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
            OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        )
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        JCA_ASYMMETRIC_CIPHER_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.OAEP_SHA256),
        JcaCipherConfiguration(
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
            OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
        )
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        JCA_ASYMMETRIC_CIPHER_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.OAEP_SHA384),
        JcaCipherConfiguration(
            "RSA/ECB/OAEPWithSHA-384AndMGF1Padding",
            OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT)
        )
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        JCA_ASYMMETRIC_CIPHER_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.OAEP_SHA512),
        JcaCipherConfiguration(
            "RSA/ECB/OAEPWithSHA-512AndMGF1Padding",
            OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT)
        )
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        JCA_ASYMMETRIC_CIPHER_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.PKCS1),
        JcaCipherConfiguration("RSA/ECB/PKCS1Padding", null)
    )
    AlgorithmRegistry.registerAsymmetricMapping(
        JCA_ASYMMETRIC_CIPHER_NAMESPACE,
        AsymmetricEncryptionMappingKey(RsaEncryptionPadding.NONE),
        JcaCipherConfiguration("RSA/ECB/NoPadding", null)
    )
}

/** Get a pre-configured JCA instance for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstance(provider: String? = null): KmmResult<JcaSignature> = catching {
    jcaBuiltInMappings
    AlgorithmRegistry.findSignatureMapping<JcaSignatureFactory>(JCA_SIGNATURE_NAMESPACE, this)
        ?.create(provider)
        ?: throw UnsupportedCryptoException("Unsupported signature algorithm $this")
}

internal expect fun RsaSignatureAlgorithm.getRSAPlatformSignatureInstance(provider: String?): JcaSignature

/** Get a pre-configured JCA instance for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstance(provider: String? = null) =
    this.algorithm.getJCASignatureInstance(provider)

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstancePreHashed(provider: String? = null): KmmResult<JcaSignature> = catching {
    jcaBuiltInMappings
    AlgorithmRegistry.findSignatureMapping<JcaSignatureFactory>(JCA_SIGNATURE_PREHASHED_NAMESPACE, this)
        ?.create(provider)
        ?: throw UnsupportedCryptoException("Unsupported pre-hashed signature algorithm $this")
}

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstancePreHashed(provider: String? = null) =
    this.algorithm.getJCASignatureInstancePreHashed(provider)


val Digest.jcaName
    get() = when (this) {
        Digest.SHA256 -> "SHA-256"
        Digest.SHA384 -> "SHA-384"
        Digest.SHA512 -> "SHA-512"
        Digest.SHA1 -> "SHA-1"
    }


val Digest?.jcaAlgorithmComponent
    get() = when (this) {
        null -> "NONE"
        Digest.SHA1 -> "SHA1"
        Digest.SHA256 -> "SHA256"
        Digest.SHA384 -> "SHA384"
        Digest.SHA512 -> "SHA512"
    }

val ECCurve.jcaName
    get() = when (this) {
        ECCurve.SECP_256_R_1 -> "secp256r1"
        ECCurve.SECP_384_R_1 -> "secp384r1"
        ECCurve.SECP_521_R_1 -> "secp521r1"
    }

fun ECCurve.Companion.byJcaName(name: String): ECCurve? = ECCurve.entries.find { it.jcaName == name }


@Deprecated("renamed", ReplaceWith("toJcaPublicKey()"), DeprecationLevel.ERROR)
fun CryptoPublicKey.getJcaPublicKey() = toJcaPublicKey()
fun PublicKey.toJcaPublicKey() = when (this) {
    is PublicKey.EC -> toJcaPublicKey()
    is PublicKey.RSA -> toJcaPublicKey()
}

@Deprecated("renamed", ReplaceWith("toJcaPublicKey()"), DeprecationLevel.ERROR)
fun PublicKey.EC.getJcaPublicKey() = toJcaPublicKey()
fun PublicKey.EC.toJcaPublicKey(): KmmResult<ECPublicKey> = catching {
    val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
    val x = x.residue.toJavaBigInteger()
    val y = y.residue.toJavaBigInteger()
    val ecPoint = parameterSpec.curve.createPoint(x, y)
    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
    JCEECPublicKey("EC", ecPublicKeySpec)
}

private val rsaFactory = KeyFactory.getInstance("RSA")

@Deprecated("renamed", ReplaceWith("toJcaPublicKey()"), DeprecationLevel.ERROR)
fun PublicKey.RSA.getJcaPublicKey(): KmmResult<RSAPublicKey> = toJcaPublicKey()
fun PublicKey.RSA.toJcaPublicKey(): KmmResult<RSAPublicKey> = catching {
    rsaFactory.generatePublic(
        RSAPublicKeySpec(n.toJavaBigInteger(), e.toJavaBigInteger())
    ) as RSAPublicKey
}

@Deprecated("replaced by extension", ReplaceWith("publicKey.toPublicKey()"), DeprecationLevel.ERROR)
fun PublicKey.EC.Companion.fromJcaPublicKey(publicKey: ECPublicKey): KmmResult<PublicKey.EC> =
    publicKey.toPublicKey()

fun ECPublicKey.toPublicKey(): KmmResult<PublicKey.EC> = catching {
    val curve = ECCurve.byJcaName(
        SECNamedCurves.getName(
            SubjectPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(encoded)
            ).algorithm.parameters as ASN1ObjectIdentifier
        )
    ) ?: throw SerializationException("Unknown Jca name")
    PublicKey.EC.fromUncompressed(
        curve,
        w.affineX.toByteArray().ensureSize(curve.coordinateLength.bytes),
        w.affineY.toByteArray().ensureSize(curve.coordinateLength.bytes)
    )
}

@Deprecated("Renamed to toPublicKey().", ReplaceWith("toPublicKey()"))
fun ECPublicKey.toCryptoPublicKey(): KmmResult<PublicKey.EC> = toPublicKey()

@Deprecated("replaced by extension", ReplaceWith("publicKey.toPublicKey()"), DeprecationLevel.ERROR)
fun PublicKey.RSA.Companion.fromJcaPublicKey(publicKey: RSAPublicKey): KmmResult<PublicKey.RSA> =
    publicKey.toPublicKey()

fun RSAPublicKey.toPublicKey(): KmmResult<PublicKey.RSA> =
    catching { PublicKey.RSA(modulus.toAsn1Integer(), publicExponent.toAsn1Integer()) }

@Deprecated("Renamed to toPublicKey().", ReplaceWith("toPublicKey()"))
fun RSAPublicKey.toCryptoPublicKey(): KmmResult<PublicKey.RSA> = toPublicKey()


@Deprecated("replaced by extension", ReplaceWith("publicKey.toPublicKey()"), DeprecationLevel.ERROR)
fun PublicKey.Companion.fromJcaPublicKey(publicKey: JcaPublicKey): KmmResult<PublicKey> =
    publicKey.toPublicKey()

fun JcaPublicKey.toPublicKey(): KmmResult<PublicKey> =
    when (this) {
        is RSAPublicKey -> toPublicKey()
        is ECPublicKey -> toPublicKey()
        else -> KmmResult.failure(IllegalArgumentException("Unsupported Key Type"))
    }

@Deprecated("Renamed to toPublicKey().", ReplaceWith("toPublicKey()"))
fun JcaPublicKey.toCryptoPublicKey(): KmmResult<PublicKey> = toPublicKey()

/**
 * In Java EC signatures are returned as DER-encoded, RSA signatures however are raw bytearrays
 */
val Signature.jcaSignatureBytes: ByteArray
    get() = when (this) {
        is Signature.EC -> encodeToDer()
        is Signature.RSA -> rawByteArray
    }

/**
 * In Java EC signatures are returned as DER-encoded, RSA signatures however are raw bytearrays
 */
fun Signature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SignatureAlgorithm
): Signature =
    if (algorithm is EcdsaSignatureAlgorithm)
        Signature.EC.parseFromJca(input)
    else
        Signature.RSA.parseFromJca(input)

fun Signature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SpecializedSignatureAlgorithm
) = parseFromJca(input, algorithm.algorithm)

/**
 * Parses a signature produced by the JCA digestwithECDSA algorithm.
 */
fun Signature.EC.Companion.parseFromJca(input: ByteArray) =
    Signature.EC.decodeFromDer(input)

/**
 * Parses a signature produced by the JCA digestWithECDSAinP1363Format algorithm.
 */
fun Signature.EC.Companion.parseFromJcaP1363(input: ByteArray) =
    Signature.EC.fromRawBytes(input)

fun Signature.RSA.Companion.parseFromJca(input: ByteArray) =
    Signature.RSA(input)

/**
 * Converts this [X509Certificate] to a [java.security.cert.X509Certificate].
 * This function is suspending, because it uses a mutex to lock the underlying certificate factory (which is reused for performance reasons
 */
suspend fun Certificate.toJcaCertificate(): KmmResult<java.security.cert.X509Certificate> = catching {
    certificateFactoryMutex.withLock {
        certFactory.generateCertificate(encodeToDer().inputStream()) as java.security.cert.X509Certificate
    }
}

/**
 * blocking implementation of [toJcaCertificate]
 */
fun Certificate.toJcaCertificateBlocking(): KmmResult<java.security.cert.X509Certificate> =
    runBlocking { toJcaCertificate() }

/**
 * Converts this [java.security.cert.X509Certificate] to an [Certificate]
 */
fun java.security.cert.X509Certificate.toKmpCertificate() =
    catching { Certificate.decodeFromDer(encoded) }

fun PrivateKey.WithPublicKey<*>.toJcaPrivateKey(): KmmResult<JcaPrivateKey> = catching {
    val spec = PKCS8EncodedKeySpec(asPKCS8.encodeToDer())
    val kf = when (this) {
        is PrivateKey.EC.WithPublicKey -> KeyFactory.getInstance("EC")
        is PrivateKey.RSA -> KeyFactory.getInstance("RSA")
    }
    kf.generatePrivate(spec)!!
}

fun PrivateKey.EC.WithPublicKey.toJcaPrivateKey(): KmmResult<ECPrivateKey> =
    (this as PrivateKey.WithPublicKey<*>).toJcaPrivateKey().mapCatching { it as ECPrivateKey }

fun PrivateKey.RSA.toJcaPrivateKey(): KmmResult<RSAPrivateKey> =
    (this as PrivateKey.WithPublicKey<*>).toJcaPrivateKey().mapCatching { it as RSAPrivateKey }

fun JcaPrivateKey.toPrivateKey(): KmmResult<PrivateKey.WithPublicKey<*>> =
    catching { PrivateKey.decodeFromDer(encoded) as PrivateKey.WithPublicKey<*> }

fun ECPrivateKey.toPrivateKey(): KmmResult<PrivateKey.EC.WithPublicKey> =
    catching { PrivateKey.EC.decodeFromDer(encoded) as PrivateKey.EC.WithPublicKey }

fun RSAPrivateKey.toPrivateKey(): KmmResult<PrivateKey.RSA> =
    catching { PrivateKey.RSA.decodeFromDer(encoded) }


val SymmetricEncryptionAlgorithm<*, *, *>.jcaName: String
    @OptIn(HazardousMaterials::class)
    get() = when (this) {
        is AesGcmAlgorithm -> "AES/GCM/NoPadding"
        is AesCbcBase<*, *> -> "AES/CBC/PKCS5Padding"
        is AesEcbAlgorithm -> "AES/ECB/PKCS5Padding"
        is AesWrapAlgorithm -> "AESWrap"
        ChaCha20Poly1305Algorithm -> "ChaCha20-Poly1305"
        else -> throw UnsupportedCryptoException("$this is unsupported")
    }

val SymmetricEncryptionAlgorithm<*, *, *>.jcaKeySpec: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES<*, *, *> -> "AES"
        ChaCha20Poly1305Algorithm -> "ChaCha20"
        else -> throw UnsupportedCryptoException("$this keyspec is unsupported")
    }

val HmacAlgorithm.jcaName: String
    get() = when (this) {
        MessageAuthenticationCode.HMAC_SHA1 -> "HmacSHA1"
        MessageAuthenticationCode.HMAC_SHA256 -> "HmacSHA256"
        MessageAuthenticationCode.HMAC_SHA384 -> "HmacSHA384"
        MessageAuthenticationCode.HMAC_SHA512 -> "HmacSHA512"
        else -> throw UnsupportedCryptoException("Unsupported HMAC algorithm $this")
    }

/**
 * An encryption algorithm's JCA name. This is publicly exposed because it could come in handy under _very specific_ circumstances.
 * **Double and triple check before feeding this into `Cipher.getInstance`!**.
 * Then think again, pull in Signum Supreme and call `encryptorFor`/`decryptorFor` on whatever pre-configured instance of
 * [AsymmetricEncryptionAlgorithm] you will be actually using.
 */
val AsymmetricEncryptionAlgorithm.jcaName: String
    get() {
        jcaBuiltInMappings
        return AlgorithmRegistry.findAsymmetricMapping<JcaCipherConfiguration>(JCA_ASYMMETRIC_CIPHER_NAMESPACE, this)
            ?.transformation
            ?: throw UnsupportedCryptoException("Unsupported asymmetric encryption algorithm $this")
    }

/**
 * An encryption algorithm's JCA parameters. This is publicly exposed because it could come in handy under _very specific_ circumstances.
 * **Double and triple check before feeding this into `Cipher.init`!**.
 * Then think again, pull in Signum Supreme and call `encryptorFor`/`decryptorFor` on whatever pre-configured instance of
 * [AsymmetricEncryptionAlgorithm] you will be actually using.
 */
val AsymmetricEncryptionAlgorithm.jcaParameterSpec: AlgorithmParameterSpec?
    get() {
        jcaBuiltInMappings
        return AlgorithmRegistry.findAsymmetricMapping<JcaCipherConfiguration>(JCA_ASYMMETRIC_CIPHER_NAMESPACE, this)
            ?.parameterSpec
            ?: throw UnsupportedCryptoException("Unsupported asymmetric encryption algorithm $this")
    }

/** Get a pre-configured JCA Cipher instance for this algorithm to use for **encryption** */
fun AsymmetricEncryptionAlgorithm.getJCAEncryptorInstance(publicKey: PublicKey.RSA, provider: String? = null) =
    catching {
        (if (provider != null) Cipher.getInstance(jcaName, provider) else Cipher.getInstance(jcaName)).apply {
            init(Cipher.ENCRYPT_MODE, publicKey.toJcaPublicKey().getOrThrow(), jcaParameterSpec)
        }
    }

/** Get a pre-configured JCA Cipher instance for this algorithm to use for **decryption** */
fun AsymmetricEncryptionAlgorithm.getJCADecryptorInstance(privateKey: PrivateKey.RSA, provider: String? = null) =
    catching {
        (if (provider != null) Cipher.getInstance(jcaName, provider) else Cipher.getInstance(jcaName)).apply {
            init(Cipher.DECRYPT_MODE, privateKey.toJcaPrivateKey().getOrThrow(), jcaParameterSpec)
        }
    }
