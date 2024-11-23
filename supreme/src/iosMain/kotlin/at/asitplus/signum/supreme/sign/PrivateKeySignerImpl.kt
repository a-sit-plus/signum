package at.asitplus.signum.supreme.sign

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
    algorithm: SignatureAlgorithm.RSA
): Signer.RSA = RSAPrivateKeySigner(key, algorithm, key.publicKey)

@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC,
    algorithm: SignatureAlgorithm.ECDSA
): Signer.ECDSA = ECPrivateKeySigner(key, algorithm, key.publicKey!!)


sealed class PrivateKeySigner<K: KeyType> @OptIn(ExperimentalForeignApi::class)
protected constructor(
    internal val privateKey: SecKeyRef,
    override val signatureAlgorithm: SignatureAlgorithm<K>,
) : Signer<K> {
    override val mayRequireUserUnlock: Boolean get() = false

    @OptIn(ExperimentalForeignApi::class)
    override suspend fun sign(data: SignatureInput) = signCatching {
        val inputData = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow()
        val algorithm = signatureAlgorithm.secKeyAlgorithmPreHashed
        val input = inputData.data.single().toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKey, algorithm, input.giveToCF(), error)
        }.let { it.takeFromCF<NSData>().toByteArray() }
        return@signCatching when (val pubkey = publicKey) {
            is CryptoPublicKey.EC -> CryptoSignature.EC.decodeFromDer(signatureBytes).withCurve(pubkey.curve)
            is CryptoPublicKey.RSA -> CryptoSignature.RSAorHMAC(signatureBytes)
        }
    }
}


@OptIn(ExperimentalForeignApi::class)
class ECPrivateKeySigner(
    privateKey: CryptoPrivateKey.EC,
    override val signatureAlgorithm: SignatureAlgorithm.ECDSA,
    override val publicKey: CryptoPublicKey.EC
) : PrivateKeySigner<KeyType.EC>(privateKey.toSecKey().getOrThrow(), signatureAlgorithm), Signer.ECDSA

@OptIn(ExperimentalForeignApi::class)
class RSAPrivateKeySigner(
    privateKey: CryptoPrivateKey.RSA,
    override val signatureAlgorithm: SignatureAlgorithm.RSA,
    override val publicKey: CryptoPublicKey.RSA
) : PrivateKeySigner<KeyType.RSA>(privateKey.toSecKey().getOrThrow(), signatureAlgorithm), Signer.RSA