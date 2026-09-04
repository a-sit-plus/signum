package at.asitplus.signum.indispensable.sign

interface ECDSAVerifier : SignatureVerifier {
    override val signatureAlgorithm: ECDSAAlgorithm
    override val publicKey: ECDSAPublicKey
}

interface RSAVerifier : SignatureVerifier {
    override val signatureAlgorithm: RSAAlgorithm
    override val publicKey: RSAPublicKey
}