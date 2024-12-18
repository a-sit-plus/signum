package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.*
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSData
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyRef


@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.RSA,
    algorithm: SignatureAlgorithm.RSA
): Signer.RSA = RSAPrivateKeySigner(key, algorithm, key.publicKey)

@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC.WithPublicKey,
    algorithm: SignatureAlgorithm.ECDSA
): Signer.ECDSA = ECPrivateKeySigner(key, algorithm, key.publicKey)


sealed class PrivateKeySigner @OptIn(ExperimentalForeignApi::class)
protected constructor(
    internal val secKey: SecKeyRef,
    override val signatureAlgorithm: SignatureAlgorithm,
) : Signer {


    protected abstract val privateKey: CryptoPrivateKey.WithPublicKey<*>

    override val mayRequireUserUnlock: Boolean get() = false

    @OptIn(ExperimentalForeignApi::class)
    override suspend fun sign(data: SignatureInput) = signCatching {
        val inputData = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow()
        val algorithm = signatureAlgorithm.secKeyAlgorithmPreHashed
        val input = inputData.data.single().toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(secKey, algorithm, input.giveToCF(), error)
        }.let { it.takeFromCF<NSData>().toByteArray() }
        return@signCatching when (val pubkey = publicKey) {
            is CryptoPublicKey.EC -> CryptoSignature.EC.decodeFromDer(signatureBytes).withCurve(pubkey.curve)
            is CryptoPublicKey.RSA -> CryptoSignature.RSAorHMAC(signatureBytes)
        }
    }

    @SecretExposure
    override fun exportPrivateKey() = KmmResult.success(privateKey)
}


@OptIn(ExperimentalForeignApi::class)
class ECPrivateKeySigner(
    override val privateKey: CryptoPrivateKey.EC.WithPublicKey,
    override val signatureAlgorithm: SignatureAlgorithm.ECDSA,
    override val publicKey: CryptoPublicKey.EC
) : PrivateKeySigner(privateKey.toSecKey().getOrThrow(), signatureAlgorithm), Signer.ECDSA

@OptIn(ExperimentalForeignApi::class)
class RSAPrivateKeySigner(
    override val privateKey: CryptoPrivateKey.RSA,
    override val signatureAlgorithm: SignatureAlgorithm.RSA,
    override val publicKey: CryptoPublicKey.RSA
) : PrivateKeySigner(privateKey.toSecKey().getOrThrow(), signatureAlgorithm), Signer.RSA