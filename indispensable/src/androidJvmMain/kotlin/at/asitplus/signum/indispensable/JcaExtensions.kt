package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.awesn1.toJavaBigInteger
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.integrity.HMAC
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SpecializedSignatureAlgorithm
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.JCAProviderRefO
import at.asitplus.signum.dsl.Of
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.internals.ImplementationError
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
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.security.PrivateKey as JCAPrivateKey
import java.security.PublicKey as JCAPublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


private val certificateFactoryMutex = Mutex()
private val certFactory = CertificateFactory.getInstance("X.509")

internal val RSAAlgorithm.Parameters.PssPadded.jcaPSSParams : PSSParameterSpec get() {
    val mgfAlgorithm = mgfAlgorithm
    if (mgfAlgorithm !is RSAAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1)
        throw UnsupportedCryptoException("Only Pkcs1MGF1 is supported")
    val outerDigest = digest
    if (outerDigest !is WellKnownDigest)
        throw UnsupportedCryptoException("Unknown outer digest")
    val innerDigest = mgfAlgorithm.digest
    if (innerDigest !is WellKnownDigest)
        throw UnsupportedCryptoException("Unknown inner digest")
    return PSSParameterSpec(
        outerDigest.jcaName,
        "MGF1",
        when (innerDigest) {
            WellKnownDigest.SHA1 -> MGF1ParameterSpec.SHA1
            WellKnownDigest.SHA256 -> MGF1ParameterSpec.SHA256
            WellKnownDigest.SHA384 -> MGF1ParameterSpec.SHA384
            WellKnownDigest.SHA512 -> MGF1ParameterSpec.SHA512
        },
        saltLength.toInt(),
        trailerField
    )
}

internal fun sigGetInstance(alg: String, provider: JCAProviderRef): Signature =
    when (provider) {
        is JCAProviderRef.ByName -> Signature.getInstance(alg, provider.provider)
        is JCAProviderRefO -> Signature.getInstance(alg, provider.provider)
        is JCAProviderRef.None -> Signature.getInstance(alg)
        else -> throw ImplementationError("invalid JCAProvider ref")
    }

interface JcaMappingProvider {
    /**
     * Should return a pre-configured JCA [MessageDigest] instance for this recognized digest, ready for
     * [MessageDigest.update]/[MessageDigest.digest]. This also powers `.digest` on JVM targets if Supreme is loaded.
     */
    fun getJCAMessageDigestInstance(digest: Digest, jcaProviderRef: JCAProviderRef): MessageDigest? { return null }

    /**
     * Should return a pre-configured JCA [Signature] instance for this recognized algorithm, ready for
     * [Signature.initSign]/[Signature.initVerify]. This allows integration into Supreme's signer providers.
     * - If the algorithm is not recognized, the provider should return `null`.
     * - If the algorithm is recognized but its particular configuration is unsupported by the JCA, the provider should throw [UnsupportedCryptoException].
     * - If the provider does not wish to implement mapping this algorithm for the JCA, it can choose to return `null`, allowing fall-through.
     *
     * The [jcaProviderRef], if non-`null`, should be respected and passed to the JCA.
     * If the provided algorithm is unsupported by the provider in question, the JCA may then throw [NoSuchAlgorithmException].
     * This is intended. The [SignatureAlgorithm.getJCASignatureInstance] wrapper will map this to [UnsupportedCryptoException].
     */
    fun getJCASignatureInstance(algorithm: SignatureAlgorithm, jcaProviderRef: JCAProviderRef): Signature? { return null }

    /**
     * Should return a pre-configured JCA [Signature] instance for this algorithm, ready for [Signature.initSign]/[Signature.initVerify].
     * This instance should accept pre-hashed input data. Its output should be identical to providing the pre-image to [getJCASignatureInstance].
     * If this is impossible for the algorithm, for example because the pre-hashed version uses different domain separators, [UnsupportedCryptoException] should be thrown.
     *
     * All other implementor notes from [getJCASignatureInstance] also apply.
     */
    fun getJCASignatureInstancePreHashed(algorithm: SignatureAlgorithm, jcaProviderRef: JCAProviderRef): Signature? { return null }

    /** Maps this CryptoPublicKey to a JCA PublicKey instance. */
    fun cryptoPublicKeyToJcaPublicKey(publicKey: CryptoPublicKey): JCAPublicKey? { return null }

    /** Maps this JCA PublicKey instance to a CryptoPublicKey. */
    fun jcaPublicKeyToCryptoPublicKey(publicKey: JCAPublicKey): CryptoPublicKey? { return null }

    /** Maps this CryptoPrivateKey to a JCA PrivateKey instance. */
    fun cryptoPrivateKeyToJcaPrivateKey(privateKey: CryptoPrivateKey): JCAPrivateKey? { return null }

    /** Maps this JCA PrivateKey instance to a CryptoPrivateKey. */
    fun jcaPrivateKeyToCryptoPrivateKey(privateKey: JCAPrivateKey): CryptoPrivateKey.WithPublicKey? { return null }
}

/** Get a pre-configured JCA [MessageDigest] instance for this digest */
fun Digest.getJCAMessageDigestInstance(provider: JCAProviderRef) =
    ServiceLoader.load<JcaMappingProvider>().get(this)
        { getJCAMessageDigestInstance(it, provider) }

/** Get a pre-configured JCA [MessageDigest] instance for this digest */
fun Digest.getJCAMessageDigestInstance(provider: String? = null) =
    getJCAMessageDigestInstance(JCAProviderRef.Of(provider))

/** Get a pre-configured JCA [MessageDigest] instance for this digest */
fun Digest.getJCAMessageDigestInstance(provider: Provider?) =
    getJCAMessageDigestInstance(JCAProviderRef.Of(provider))

/** Get a pre-configured JCA instance for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstance(provider: JCAProviderRef) =
    ServiceLoader.load<JcaMappingProvider>().get(this)
        { getJCASignatureInstance(it, provider) }

/** Get a pre-configured JCA instance for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstance(provider: String? = null) =
    getJCASignatureInstance(JCAProviderRef.Of(provider))

/** Get a pre-configured JCA instance for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstance(provider: Provider?) =
    getJCASignatureInstance(JCAProviderRef.Of(provider))

/** Get a pre-configured JCA instance for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstance(provider: JCAProviderRef) =
    this.algorithm.getJCASignatureInstance(provider)

/** Get a pre-configured JCA instance for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstance(provider: String? = null) =
    this.algorithm.getJCASignatureInstance(provider)

/** Get a pre-configured JCA instance for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstance(provider: Provider?) =
    this.algorithm.getJCASignatureInstance(provider)

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstancePreHashed(provider: JCAProviderRef) =
    ServiceLoader.load<JcaMappingProvider>().get(this)
        { getJCASignatureInstancePreHashed(it, provider) }

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstancePreHashed(provider: String? = null) =
    getJCASignatureInstancePreHashed(JCAProviderRef.Of(provider))

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstancePreHashed(provider: Provider?) =
    getJCASignatureInstancePreHashed(JCAProviderRef.Of(provider))

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstancePreHashed(provider: JCAProviderRef) =
    this.algorithm.getJCASignatureInstancePreHashed(provider)

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstancePreHashed(provider: String? = null) =
    this.algorithm.getJCASignatureInstancePreHashed(JCAProviderRef.Of(provider))

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstancePreHashed(provider: Provider?) =
    this.algorithm.getJCASignatureInstancePreHashed(JCAProviderRef.Of(provider))

internal val WellKnownDigest.jcaName
    get() = when (this) {
        WellKnownDigest.SHA1 -> "SHA-1"
        WellKnownDigest.SHA256 -> "SHA-256"
        WellKnownDigest.SHA384 -> "SHA-384"
        WellKnownDigest.SHA512 -> "SHA-512"
    }


internal val WellKnownDigest?.jcaAlgorithmComponent
    get() = when (this) {
        null -> "NONE"
        WellKnownDigest.SHA1 -> "SHA1"
        WellKnownDigest.SHA256 -> "SHA256"
        WellKnownDigest.SHA384 -> "SHA384"
        WellKnownDigest.SHA512 -> "SHA512"
    }

val ECCurve.jcaName
    get() = when (this) {
        ECCurve.SECP_256_R_1 -> "secp256r1"
        ECCurve.SECP_384_R_1 -> "secp384r1"
        ECCurve.SECP_521_R_1 -> "secp521r1"
    }

fun ECCurve.Companion.byJcaName(name: String): ECCurve? = ECCurve.entries.find { it.jcaName == name }


fun CryptoPublicKey.toJcaPublicKey() =
    ServiceLoader.load<JcaMappingProvider>().get(this, JcaMappingProvider::cryptoPublicKeyToJcaPublicKey)

fun ECDSAPublicKey.toJcaPublicKey(): java.security.interfaces.ECPublicKey {
    val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
    val x = x.residue.toJavaBigInteger()
    val y = y.residue.toJavaBigInteger()
    val ecPoint = parameterSpec.curve.createPoint(x, y)
    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
    return JCEECPublicKey("EC", ecPublicKeySpec)
}

private val rsaFactory = KeyFactory.getInstance("RSA")

fun RSAPublicKey.toJcaPublicKey(): java.security.interfaces.RSAPublicKey =
    rsaFactory.generatePublic(
        RSAPublicKeySpec(n.toJavaBigInteger(), e.toJavaBigInteger())
    ) as java.security.interfaces.RSAPublicKey

fun java.security.interfaces.ECPublicKey.toCryptoPublicKey(): ECDSAPublicKey {
    // TODO: don't we have "curve by oid" now?
    val curve = ECCurve.byJcaName(
        SECNamedCurves.getName(
            SubjectPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(encoded)
            ).algorithm.parameters as ASN1ObjectIdentifier
        )
    ) ?: throw SerializationException("Unknown Jca name")
    return ECDSAPublicKey.fromUncompressed(
        curve,
        w.affineX.toByteArray(),
        w.affineY.toByteArray()
    )
}

fun java.security.interfaces.RSAPublicKey.toCryptoPublicKey(): RSAPublicKey =
    RSAPublicKey(modulus.toAsn1Integer(), publicExponent.toAsn1Integer())

fun JCAPublicKey.toCryptoPublicKey(): CryptoPublicKey =
    ServiceLoader.load<JcaMappingProvider>()
        .get(this, JcaMappingProvider::jcaPublicKeyToCryptoPublicKey)

/**
 * Converts this [Certificate] to a [java.security.cert.X509Certificate].
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

fun CryptoPrivateKey.toJcaPrivateKey() =
    ServiceLoader.load<JcaMappingProvider>()
        .get(this, JcaMappingProvider::cryptoPrivateKeyToJcaPrivateKey)

fun ECDSAPrivateKey.toJcaPrivateKey() =
    KeyFactory.getInstance("EC")
        .generatePrivate(PKCS8EncodedKeySpec(asPKCS8.encodeToDer()))
            as java.security.interfaces.ECPrivateKey

fun RSAPrivateKey.toJcaPrivateKey() =
    KeyFactory.getInstance("RSA")
        .generatePrivate(PKCS8EncodedKeySpec(asPKCS8.encodeToDer()))
            as java.security.interfaces.RSAPrivateKey

fun JCAPrivateKey.toCryptoPrivateKey() =
    ServiceLoader.load<JcaMappingProvider>()
        .get(this, JcaMappingProvider::jcaPrivateKeyToCryptoPrivateKey)

fun java.security.interfaces.ECPrivateKey.toCryptoPrivateKey(): ECDSAPrivateKey.WithPublicKey =
    ECDSAPrivateKey.decodeFromDer(encoded) as ECDSAPrivateKey.WithPublicKey

fun java.security.interfaces.RSAPrivateKey.toCryptoPrivateKey(): RSAPrivateKey =
    RSAPrivateKey.decodeFromDer(encoded)


val SymmetricEncryptionAlgorithm<*, *, *>.jcaName: String
    @OptIn(HazardousMaterials::class)
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is SymmetricEncryptionAlgorithm.AES.CBC<*, *> -> "AES/CBC/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.AES.ECB -> "AES/ECB/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.AES.ECB_NOPADDING -> "AES/ECB/NoPadding"
        is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394 -> "AESWrap"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20-Poly1305"
        //else -> TODO("$this is unsupported")
    }

val SymmetricEncryptionAlgorithm<*, *, *>.jcaKeySpec: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES<*, *, *> -> "AES"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20"
        //else -> TODO("$this keyspec is unsupported UNSUPPORTED")
    }

val HMAC.jcaName: String
    get() = when (this) {
        HMAC.SHA1 -> "HmacSHA1"
        HMAC.SHA256 -> "HmacSHA256"
        HMAC.SHA384 -> "HmacSHA384"
        HMAC.SHA512 -> "HmacSHA512"
        else -> TODO("providerize")
    }

/**
 * An encryption algorithm's JCA name. This is publicly exposed because it could come in handy under _very specific_ circumstances.
 * **Double and triple check before feeding this into `Cipher.getInstance`!**.
 * Then think again, pull in Signum Supreme and call `encryptorFor`/`decryptorFor` on whatever pre-configured instance of
 * [AsymmetricEncryptionAlgorithm] you will be actually using.
 */
val AsymmetricEncryptionAlgorithm.jcaName: String
    get() = when (this) {
        is AsymmetricEncryptionAlgorithm.RSA -> when (padding) {
            at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA1 -> "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
            at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA256 -> "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA384 -> "RSA/ECB/OAEPWithSHA-384AndMGF1Padding"
            at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA512 -> "RSA/ECB/OAEPWithSHA-512AndMGF1Padding"
            @OptIn(HazardousMaterials::class)
            at.asitplus.signum.indispensable.asymmetric.RSAPadding.PKCS1 -> "RSA/ECB/PKCS1Padding"

            @OptIn(HazardousMaterials::class)
            at.asitplus.signum.indispensable.asymmetric.RSAPadding.NONE -> "RSA/ECB/NoPadding"
        }
    }

/**
 * An encryption algorithm's JCA parameters. This is publicly exposed because it could come in handy under _very specific_ circumstances.
 * **Double and triple check before feeding this into `Cipher.init`!**.
 * Then think again, pull in Signum Supreme and call `encryptorFor`/`decryptorFor` on whatever pre-configured instance of
 * [AsymmetricEncryptionAlgorithm] you will be actually using.
 */
val AsymmetricEncryptionAlgorithm.jcaParameterSpec: AlgorithmParameterSpec?
    get() =
        when (this) {
            is AsymmetricEncryptionAlgorithm.RSA -> when (padding) {
                @OptIn(HazardousMaterials::class)
                at.asitplus.signum.indispensable.asymmetric.RSAPadding.NONE -> null

                at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA1 -> OAEPParameterSpec(
                    "SHA-1",
                    "MGF1",
                    MGF1ParameterSpec.SHA1,
                    PSource.PSpecified.DEFAULT
                )

                at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA256 -> OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
                )

                at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA384 -> OAEPParameterSpec(
                    "SHA-384",
                    "MGF1",
                    MGF1ParameterSpec.SHA384,
                    PSource.PSpecified.DEFAULT
                )

                at.asitplus.signum.indispensable.asymmetric.RSAPadding.OAEP.SHA512 -> OAEPParameterSpec(
                    "SHA-512",
                    "MGF1",
                    MGF1ParameterSpec.SHA512,
                    PSource.PSpecified.DEFAULT
                )

                @OptIn(HazardousMaterials::class)
                at.asitplus.signum.indispensable.asymmetric.RSAPadding.PKCS1 -> null
            }
        }

/** Get a pre-configured JCA Cipher instance for this algorithm to use for **encryption** */
fun AsymmetricEncryptionAlgorithm.getJCAEncryptorInstance(publicKey: RSAPublicKey, provider: String? = null) =
    catching {
        (if (provider != null) Cipher.getInstance(jcaName, provider) else Cipher.getInstance(jcaName)).apply {
            init(Cipher.ENCRYPT_MODE, publicKey.toJcaPublicKey(), jcaParameterSpec)
        }
    }

/** Get a pre-configured JCA Cipher instance for this algorithm to use for **decryption** */
fun AsymmetricEncryptionAlgorithm.getJCADecryptorInstance(privateKey: RSAPrivateKey, provider: String? = null) =
    catching {
        (if (provider != null) Cipher.getInstance(jcaName, provider) else Cipher.getInstance(jcaName)).apply {
            init(Cipher.DECRYPT_MODE, privateKey.toJcaPrivateKey(), jcaParameterSpec)
        }
    }
