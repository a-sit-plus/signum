package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.Indispensable

interface SignatureAlgorithm : DerEncodable<X509AlgorithmIdentifier> {

    @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
        replaceWith = ReplaceWith("EcdsaAAlgorithm"))
    typealias ECDSA = EcdsaAlgorithm

    @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
        replaceWith = ReplaceWith("RsaAlgorithm"))
    typealias RSA = RsaAlgorithm

    /** The signature input format in which this algorithm accepts pre-hashed input, if any */
    val preHashedSignatureFormat: SignatureInputFormat get() = null

    companion object: DerDecodable<X509AlgorithmIdentifier, SignatureAlgorithm> {
        init { Indispensable.init() }

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("EcdsaAlgorithm.withSHA256"))
        val ECDSAwithSHA256 get() = EcdsaAlgorithm.withSHA256
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("EcdsaAlgorithm.withSHA384"))
        val ECDSAwithSHA384 get() = EcdsaAlgorithm.withSHA384
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("EcdsaAlgorithm.withSHA512"))
        val ECDSAwithSHA512 get() = EcdsaAlgorithm.withSHA512

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RsaAlgorithm.withSHA256andPKCS1Padding"))
        val RSAwithSHA256andPKCS1Padding get() = RsaAlgorithm.withSHA256andPKCS1Padding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RsaAlgorithm.withSHA384andPKCS1Padding"))
        val RSAwithSHA384andPKCS1Padding get() = RsaAlgorithm.withSHA384andPKCS1Padding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RsaAlgorithm.withSHA512andPKCS1Padding"))
        val RSAwithSHA512andPKCS1Padding get() = RsaAlgorithm.withSHA512andPKCS1Padding

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RsaAlgorithm.withSHA256andPSSPadding"))
        val RSAwithSHA256andPSSPadding get() = RsaAlgorithm.withSHA256andPSSPadding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RsaAlgorithm.withSHA384andPSSPadding"))
        val RSAwithSHA384andPSSPadding get() = RsaAlgorithm.withSHA384andPSSPadding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RsaAlgorithm.withSHA512andPSSPadding"))
        val RSAwithSHA512andPSSPadding get() = RsaAlgorithm.withSHA512andPSSPadding

        override fun decodeFromTlv(element: X509AlgorithmIdentifier, der: Der) =
            ServiceLoader.load<SignatureAlgorithmsProvider>()
                .get(element, SignatureAlgorithmsProvider::getAlgorithm)

        @Deprecated("Use decodeFromTlv", replaceWith = ReplaceWith("decodeFromTlv(identifier)"))
        operator fun invoke(identifier: X509AlgorithmIdentifier): SignatureAlgorithm =
            decodeFromTlv(identifier)

    }
}

interface SpecializedSignatureAlgorithm {
    val algorithm: SignatureAlgorithm
}

interface SignatureAlgorithmsProvider {
    /** Parse a [SignatureAlgorithm] from its [X509AlgorithmIdentifier] form */
    fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier): SignatureAlgorithm?
}
