package at.asitplus.cryptotest

import at.asitplus.signum.supreme.os.SigningProvider

internal actual fun getSystemKeyStore(): SigningProvider = TODO()

/*val PROVIDER = BouncyCastleProvider()
val JVM_OPTS =
    JvmSpecifics(
        PROVIDER,
        KeyStore.getInstance("PKCS12", PROVIDER).apply { load(null, null) },
        privateKeyPassword = null
    )

internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: ByteArray?,
    withBiometricAuth: Duration?,

    ): KmmResult<TbaKey> = CryptoProvider.createSigningKey(ALIAS, alg, JVM_OPTS).map { it to listOf() }

internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm,
    signingKey: CryptoPrivateKey
): KmmResult<CryptoSignature> = CryptoProvider.sign(data, signingKey, alg)

internal actual suspend fun loadPubKey() = CryptoProvider.getPublicKey(ALIAS, JVM_OPTS)
internal actual suspend fun loadPrivateKey() = CryptoProvider.getKeyPair(ALIAS, JVM_OPTS)

internal actual suspend fun storeCertChain(): KmmResult<Unit> =
    CryptoProvider.storeCertificateChain(ALIAS + "CRT_CHAIN", SAMPLE_CERT_CHAIN, JVM_OPTS)

internal actual suspend fun getCertChain(): KmmResult<List<X509Certificate>> =
    CryptoProvider.getCertificateChain(
        ALIAS + "CRT_CHAIN", JVM_OPTS
    )*/