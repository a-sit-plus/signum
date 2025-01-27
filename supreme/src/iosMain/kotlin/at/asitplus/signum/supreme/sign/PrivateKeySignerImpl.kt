package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.*
import kotlinx.cinterop.ExperimentalForeignApi

@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.RSA,
    algorithm: SignatureAlgorithm.RSA
): Signer.RSA =
    key.toSecKey().mapCatching { EphemeralSigner.RSA(EphemeralSignerConfiguration(), it, key.publicKey, algorithm) }.getOrThrow()

@OptIn(ExperimentalForeignApi::class)
actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC.WithPublicKey,
    algorithm: SignatureAlgorithm.ECDSA
): Signer.ECDSA =
    key.toSecKey().mapCatching { EphemeralSigner.EC(EphemeralSignerConfiguration(), it, key.publicKey, algorithm) }.getOrThrow()
