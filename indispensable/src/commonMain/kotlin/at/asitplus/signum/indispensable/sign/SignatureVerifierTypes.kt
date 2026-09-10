package at.asitplus.signum.indispensable.sign

interface EcdsaVerifier : SignatureVerifier {
    override val signatureAlgorithm: EcdsaAlgorithm
    override val publicKey: EcdsaPublicKey
}

interface RsaVerifier : SignatureVerifier {
    override val signatureAlgorithm: RsaAlgorithm
    override val publicKey: RsaPublicKey
}