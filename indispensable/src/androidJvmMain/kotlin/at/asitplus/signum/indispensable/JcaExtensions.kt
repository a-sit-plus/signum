package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.toAsn1Integer
import at.asitplus.signum.indispensable.asn1.toJavaBigInteger
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
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
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.*
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

internal fun sigGetInstance(alg: String, provider: String?) =
    when (provider) {
        null -> Signature.getInstance(alg)
        else -> Signature.getInstance(alg, provider)
    }

/** Get a pre-configured JCA instance for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstance(provider: String? = null) = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withECDSA", provider)

        is SignatureAlgorithm.RSA -> getRSAPlatformSignatureInstance(provider)
    }
}

internal expect fun SignatureAlgorithm.RSA.getRSAPlatformSignatureInstance(provider: String?): Signature

/** Get a pre-configured JCA instance for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstance(provider: String? = null) =
    this.algorithm.getJCASignatureInstance(provider)

/** Get a pre-configured JCA instance for pre-hashed data for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstancePreHashed(provider: String? = null) = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA -> sigGetInstance("NONEwithECDSA", provider)
        is SignatureAlgorithm.RSA -> when (this.padding) {
            RSAPadding.PKCS1 -> when (isAndroid) {
                true -> sigGetInstance("NONEwithRSA", provider)
                false -> throw UnsupportedOperationException("Pre-hashed RSA input is unsupported on JVM")
            }

            RSAPadding.PSS -> when (isAndroid) {
                true -> sigGetInstance("NONEwithRSA/PSS", provider)
                false -> throw UnsupportedOperationException("Pre-hashed RSA input is unsupported on JVM")
            }
        }

        else -> TODO("$this is unsupported with pre-hashed data")
    }
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
fun CryptoPublicKey.toJcaPublicKey() = when (this) {
    is CryptoPublicKey.EC -> toJcaPublicKey()
    is CryptoPublicKey.RSA -> toJcaPublicKey()
}

@Deprecated("renamed", ReplaceWith("toJcaPublicKey()"), DeprecationLevel.ERROR)
fun CryptoPublicKey.EC.getJcaPublicKey() = toJcaPublicKey()
fun CryptoPublicKey.EC.toJcaPublicKey(): KmmResult<ECPublicKey> = catching {
    val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
    val x = x.residue.toJavaBigInteger()
    val y = y.residue.toJavaBigInteger()
    val ecPoint = parameterSpec.curve.createPoint(x, y)
    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
    JCEECPublicKey("EC", ecPublicKeySpec)
}

private val rsaFactory = KeyFactory.getInstance("RSA")

@Deprecated("renamed", ReplaceWith("toJcaPublicKey()"), DeprecationLevel.ERROR)
fun CryptoPublicKey.RSA.getJcaPublicKey(): KmmResult<RSAPublicKey> = toJcaPublicKey()
fun CryptoPublicKey.RSA.toJcaPublicKey(): KmmResult<RSAPublicKey> = catching {
    rsaFactory.generatePublic(
        RSAPublicKeySpec(n.toJavaBigInteger(), e.toJavaBigInteger())
    ) as RSAPublicKey
}

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
 * In Java EC signatures are returned as DER-encoded, RSA signatures however are raw bytearrays
 */
val CryptoSignature.jcaSignatureBytes: ByteArray
    get() = when (this) {
        is CryptoSignature.EC -> encodeToDer()
        is CryptoSignature.RSA -> rawByteArray
    }

/**
 * In Java EC signatures are returned as DER-encoded, RSA signatures however are raw bytearrays
 */
fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SignatureAlgorithm
): CryptoSignature =
    if (algorithm is SignatureAlgorithm.ECDSA)
        CryptoSignature.EC.parseFromJca(input)
    else
        CryptoSignature.RSA.parseFromJca(input)

fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SpecializedSignatureAlgorithm
) = parseFromJca(input, algorithm.algorithm)

/**
 * Parses a signature produced by the JCA digestwithECDSA algorithm.
 */
fun CryptoSignature.EC.Companion.parseFromJca(input: ByteArray) =
    CryptoSignature.EC.decodeFromDer(input)

/**
 * Parses a signature produced by the JCA digestWithECDSAinP1363Format algorithm.
 */
fun CryptoSignature.EC.Companion.parseFromJcaP1363(input: ByteArray) =
    CryptoSignature.EC.fromRawBytes(input)

fun CryptoSignature.RSA.Companion.parseFromJca(input: ByteArray) =
    CryptoSignature.RSA(input)

/**
 * Converts this [X509Certificate] to a [java.security.cert.X509Certificate].
 * This function is suspending, because it uses a mutex to lock the underlying certificate factory (which is reused for performance reasons
 */
suspend fun X509Certificate.toJcaCertificate(): KmmResult<java.security.cert.X509Certificate> = catching {
    certificateFactoryMutex.withLock {
        certFactory.generateCertificate(encodeToDer().inputStream()) as java.security.cert.X509Certificate
    }
}

/**
 * blocking implementation of [toJcaCertificate]
 */
fun X509Certificate.toJcaCertificateBlocking(): KmmResult<java.security.cert.X509Certificate> =
    runBlocking { toJcaCertificate() }

/**
 * Converts this [java.security.cert.X509Certificate] to an [X509Certificate]
 */
fun java.security.cert.X509Certificate.toKmpCertificate() =
    catching { X509Certificate.decodeFromDer(encoded) }

fun CryptoPrivateKey.WithPublicKey<*>.toJcaPrivateKey(): KmmResult<PrivateKey> = catching {
    val spec = PKCS8EncodedKeySpec(asPKCS8.encodeToDer())
    val kf = when (this) {
        is CryptoPrivateKey.EC.WithPublicKey -> KeyFactory.getInstance("EC")
        is CryptoPrivateKey.RSA -> KeyFactory.getInstance("RSA")
        else -> TODO("Unreachable")
    }
    kf.generatePrivate(spec)!!
}

fun CryptoPrivateKey.EC.WithPublicKey.toJcaPrivateKey(): KmmResult<ECPrivateKey> =
    (this as CryptoPrivateKey.WithPublicKey<*>).toJcaPrivateKey().mapCatching { it as ECPrivateKey }

fun CryptoPrivateKey.RSA.toJcaPrivateKey(): KmmResult<RSAPrivateKey> =
    (this as CryptoPrivateKey.WithPublicKey<*>).toJcaPrivateKey().mapCatching { it as RSAPrivateKey }

fun PrivateKey.toCryptoPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>> =
    CryptoPrivateKey.decodeFromDerSafe(encoded).mapCatching { it as CryptoPrivateKey.WithPublicKey<*> }

fun ECPrivateKey.toCryptoPrivateKey(): KmmResult<CryptoPrivateKey.EC.WithPublicKey> =
    CryptoPrivateKey.EC.decodeFromDerSafe(encoded).mapCatching { it as CryptoPrivateKey.EC.WithPublicKey }

fun RSAPrivateKey.toCryptoPrivateKey(): KmmResult<CryptoPrivateKey.RSA> =
    CryptoPrivateKey.RSA.decodeFromDerSafe(encoded)


val SymmetricEncryptionAlgorithm<*, *, *>.jcaName: String
    @OptIn(HazardousMaterials::class)
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is SymmetricEncryptionAlgorithm.AES.CBC<*, *> -> "AES/CBC/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.AES.ECB -> "AES/ECB/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394 -> "AESWrap"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20-Poly1305"
        else -> TODO("$this is unsupported")
    }

val SymmetricEncryptionAlgorithm<*, *, *>.jcaKeySpec: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES<*, *, *> -> "AES"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20"
        else -> TODO("$this keyspec is unsupported UNSUPPORTED")
    }

val HMAC.jcaName: String
    get() = when (this) {
        HMAC.SHA1 -> "HmacSHA1"
        HMAC.SHA256 -> "HmacSHA256"
        HMAC.SHA384 -> "HmacSHA384"
        HMAC.SHA512 -> "HmacSHA512"
    }

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