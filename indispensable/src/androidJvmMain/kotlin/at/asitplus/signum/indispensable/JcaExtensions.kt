package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.awesn1.toJavaBigInteger
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.integrity.HMAC
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SpecializedSignatureAlgorithm
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.digest.WellKnownDigest
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
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
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

internal val SignatureAlgorithm.RSA.Parameters.PssPadded.jcaPSSParams : PSSParameterSpec get() {
    val mgfAlgorithm = mgfAlgorithm
    if (mgfAlgorithm !is SignatureAlgorithm.RSA.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1)
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

internal fun sigGetInstance(alg: String, provider: String?): Signature =
    when (provider) {
        null -> Signature.getInstance(alg)
        else -> Signature.getInstance(alg, provider)
    }

interface JcaMappingProvider {
    /**
     * Should return a pre-configured JCA [Signature] instance for this recognized algorithm, ready for [Signature.initSign]/[Signature.initVerify].
     * This allows integration into Supreme's signer providers.
     * - If the algorithm is not recognized, the provider should return `null`.
     * - If the algorithm is recognized but its particular configuration is unsupported by the JCA, the provider should throw [UnsupportedCryptoException].
     * - If the provider does not wish to implement mapping this algorithm for the JCA, it can choose to return `null`, allowing fall-through.
     *
     * The [jcaProvider], if non-`null`, should be respected and passed to the JCA.
     * If the provided algorithm is unsupported by the provider in question, the JCA may then throw [NoSuchAlgorithmException].
     * This is intended. The [SignatureAlgorithm.getJCASignatureInstance] wrapper will map this to [UnsupportedCryptoException].
     */
    fun getJCASignatureInstance(algorithm: SignatureAlgorithm, jcaProvider: String?): Signature? { return null }

    /**
     * Should return a pre-configured JCA [Signature] instance for this algorithm, ready for [Signature.initSign]/[Signature.initVerify].
     * This instance should accept pre-hashed input data. Its output should be identical to providing the pre-image to [getJCASignatureInstance].
     * If this is impossible for the algorithm, for example because the pre-hashed version uses different domain separators, [UnsupportedCryptoException] should be thrown.
     *
     * All other implementor notes from [getJCASignatureInstance] also apply.
     */
    fun getJCASignatureInstancePreHashed(algorithm: SignatureAlgorithm, jcaProvider: String?): Signature? { return null }
}

/** Get a pre-configured JCA instance for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstance(provider: String? = null) =
    ServiceLoader.load<JcaMappingProvider>().get(this) { getJCASignatureInstance(it, provider) }

/** Get a pre-configured JCA instance for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstance(provider: String? = null) =
    this.algorithm.getJCASignatureInstance(provider)

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstancePreHashed(provider: String? = null) =
    ServiceLoader.load<JcaMappingProvider>().get(this) { getJCASignatureInstancePreHashed(it, provider) }

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstancePreHashed(provider: String? = null) =
    this.algorithm.getJCASignatureInstancePreHashed(provider)

val WellKnownDigest.jcaName
    get() = when (this) {
        WellKnownDigest.SHA1 -> "SHA-1"
        WellKnownDigest.SHA256 -> "SHA-256"
        WellKnownDigest.SHA384 -> "SHA-384"
        WellKnownDigest.SHA512 -> "SHA-512"
    }


val WellKnownDigest?.jcaAlgorithmComponent
    get() = when (this) {
        null -> "NONE"
        Digest.SHA1 -> "SHA1"
        Digest.SHA256 -> "SHA256"
        Digest.SHA384 -> "SHA384"
        Digest.SHA512 -> "SHA512"
        else -> TODO("providerization")
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
fun CryptoPublicKey.toJcaPublicKey() = when (this) {
    is CryptoPublicKey.EC -> toJcaPublicKey()
    is CryptoPublicKey.RSA -> toJcaPublicKey()
}

@Deprecated("renamed", ReplaceWith("toJcaPublicKey()"), DeprecationLevel.ERROR)
fun CryptoPublicKey.EC.getJcaPublicKey() = toJcaPublicKey()
fun CryptoPublicKey.EC.toJcaPublicKey(): ECPublicKey {
    val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
    val x = x.residue.toJavaBigInteger()
    val y = y.residue.toJavaBigInteger()
    val ecPoint = parameterSpec.curve.createPoint(x, y)
    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
    return JCEECPublicKey("EC", ecPublicKeySpec)
}

private val rsaFactory = KeyFactory.getInstance("RSA")

@Deprecated("renamed", ReplaceWith("toJcaPublicKey()"), DeprecationLevel.ERROR)
fun CryptoPublicKey.RSA.getJcaPublicKey() = toJcaPublicKey()
fun CryptoPublicKey.RSA.toJcaPublicKey(): RSAPublicKey =
    rsaFactory.generatePublic(
        RSAPublicKeySpec(n.toJavaBigInteger(), e.toJavaBigInteger())
    ) as RSAPublicKey

@Deprecated("replaced by extension", ReplaceWith("publicKey.toCryptoPublicKey()"), DeprecationLevel.ERROR)
fun CryptoPublicKey.EC.Companion.fromJcaPublicKey(publicKey: ECPublicKey): KmmResult<CryptoPublicKey.EC> =
    publicKey.toCryptoPublicKey()

fun ECPublicKey.toCryptoPublicKey(): KmmResult<CryptoPublicKey.EC> = catching {
    val curve = ECCurve.byJcaName(
        SECNamedCurves.getName(
            SubjectPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(encoded)
            ).algorithm.parameters as ASN1ObjectIdentifier
        )
    ) ?: throw SerializationException("Unknown Jca name")
    CryptoPublicKey.EC.fromUncompressed(
        curve,
        w.affineX.toByteArray(),
        w.affineY.toByteArray()
    )
}

@Deprecated("replaced by extension", ReplaceWith("publicKey.toCryptoPublicKey()"), DeprecationLevel.ERROR)
fun CryptoPublicKey.RSA.Companion.fromJcaPublicKey(publicKey: RSAPublicKey): KmmResult<CryptoPublicKey.RSA> =
    publicKey.toCryptoPublicKey()

fun RSAPublicKey.toCryptoPublicKey(): KmmResult<CryptoPublicKey.RSA> =
    catching { CryptoPublicKey.RSA(modulus.toAsn1Integer(), publicExponent.toAsn1Integer()) }


@Deprecated("replaced by extension", ReplaceWith("publicKey.toCryptoPublicKey()"), DeprecationLevel.ERROR)
fun CryptoPublicKey.Companion.fromJcaPublicKey(publicKey: PublicKey): KmmResult<CryptoPublicKey> =
    publicKey.toCryptoPublicKey()

fun PublicKey.toCryptoPublicKey(): KmmResult<CryptoPublicKey> =
    when (this) {
        is RSAPublicKey -> toCryptoPublicKey()
        is ECPublicKey -> toCryptoPublicKey()
        else -> KmmResult.failure(IllegalArgumentException("Unsupported Key Type"))
    }

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

fun CryptoPrivateKey.WithPublicKey<*>.toJcaPrivateKey(): KmmResult<PrivateKey> = catching {
    val spec = PKCS8EncodedKeySpec(asPKCS8.encodeToDer())
    val kf = when (this) {
        is CryptoPrivateKey.EC.WithPublicKey -> KeyFactory.getInstance("EC")
        is CryptoPrivateKey.RSA -> KeyFactory.getInstance("RSA")
    }
    kf.generatePrivate(spec)!!
}

fun CryptoPrivateKey.EC.WithPublicKey.toJcaPrivateKey(): KmmResult<ECPrivateKey> =
    (this as CryptoPrivateKey.WithPublicKey<*>).toJcaPrivateKey().mapCatching { it as ECPrivateKey }

fun CryptoPrivateKey.RSA.toJcaPrivateKey(): KmmResult<RSAPrivateKey> =
    (this as CryptoPrivateKey.WithPublicKey<*>).toJcaPrivateKey().mapCatching { it as RSAPrivateKey }

fun PrivateKey.toCryptoPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>> =
    catching { CryptoPrivateKey.decodeFromDer(encoded) as CryptoPrivateKey.WithPublicKey<*> }

fun ECPrivateKey.toCryptoPrivateKey(): KmmResult<CryptoPrivateKey.EC.WithPublicKey> =
    catching { CryptoPrivateKey.EC.decodeFromDer(encoded) as CryptoPrivateKey.EC.WithPublicKey }

fun RSAPrivateKey.toCryptoPrivateKey(): KmmResult<CryptoPrivateKey.RSA> =
    catching { CryptoPrivateKey.RSA.decodeFromDer(encoded) }


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
fun AsymmetricEncryptionAlgorithm.getJCAEncryptorInstance(publicKey: CryptoPublicKey.RSA, provider: String? = null) =
    catching {
        (if (provider != null) Cipher.getInstance(jcaName, provider) else Cipher.getInstance(jcaName)).apply {
            init(Cipher.ENCRYPT_MODE, publicKey.toJcaPublicKey(), jcaParameterSpec)
        }
    }

/** Get a pre-configured JCA Cipher instance for this algorithm to use for **decryption** */
fun AsymmetricEncryptionAlgorithm.getJCADecryptorInstance(privateKey: CryptoPrivateKey.RSA, provider: String? = null) =
    catching {
        (if (provider != null) Cipher.getInstance(jcaName, provider) else Cipher.getInstance(jcaName)).apply {
            init(Cipher.DECRYPT_MODE, privateKey.toJcaPrivateKey().getOrThrow(), jcaParameterSpec)
        }
    }
