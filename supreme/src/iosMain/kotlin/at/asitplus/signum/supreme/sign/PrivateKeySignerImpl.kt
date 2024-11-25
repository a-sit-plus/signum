package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.*
import at.asitplus.signum.supreme.corecall
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSData
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyRef


@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.RSA,
    algorithm: SignatureAlgorithm.RSA,
    destroySource: Boolean
): Signer.RSA = RSAPrivateKeySigner(key, algorithm, key.publicKey,destroySource)

@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC,
    algorithm: SignatureAlgorithm.ECDSA,
    destroySource: Boolean
): Signer.ECDSA = ECPrivateKeySigner(key, algorithm, key.publicKey!!,destroySource)


sealed class PrivateKeySigner @OptIn(ExperimentalForeignApi::class)
protected constructor(
    internal val secKey: SecKeyRef,
    override val signatureAlgorithm: SignatureAlgorithm,
) : Signer {


    protected abstract val privateKey: CryptoPrivateKey<*>

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
    override val privateKey: CryptoPrivateKey.EC,
    override val signatureAlgorithm: SignatureAlgorithm.ECDSA,
    override val publicKey: CryptoPublicKey.EC,
    destroySource: Boolean
) : PrivateKeySigner(privateKey.toSecKey(destroySource).getOrThrow(), signatureAlgorithm), Signer.ECDSA

@OptIn(ExperimentalForeignApi::class)
class RSAPrivateKeySigner(
    override val privateKey: CryptoPrivateKey.RSA,
    override val signatureAlgorithm: SignatureAlgorithm.RSA,
    override val publicKey: CryptoPublicKey.RSA,
    destroySource: Boolean
) : PrivateKeySigner(privateKey.toSecKey(destroySource).getOrThrow(), signatureAlgorithm), Signer.RSA