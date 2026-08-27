package at.asitplus.signum.indispensable.integrity

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.Enumeration
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.Indispensable
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAAlgorithm

//for now, we just replicate the pattern, but since everything is sealed, we don't actually parse
interface SignatureAlgorithm : DataIntegrityAlgorithm, DerEncodable<X509AlgorithmIdentifier> {

    @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
        replaceWith = ReplaceWith("ECDSAAlgorithm"))
    typealias ECDSA = ECDSAAlgorithm

    @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
        replaceWith = ReplaceWith("RSAAlgorithm"))
    typealias RSA = RSAAlgorithm

    /** The signature input format in which this algorithm accepts pre-hashed input, if any */
    val preHashedSignatureFormat: SignatureInputFormat get() = null

    companion object: DerDecodable<X509AlgorithmIdentifier, SignatureAlgorithm> {
        init { Indispensable.init() }

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("ECDSAAlgorithm.withSHA256"))
        val ECDSAwithSHA256 get() = ECDSAAlgorithm.withSHA256
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("ECDSAAlgorithm.withSHA384"))
        val ECDSAwithSHA384 get() = ECDSAAlgorithm.withSHA384
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("ECDSAAlgorithm.withSHA512"))
        val ECDSAwithSHA512 get() = ECDSAAlgorithm.withSHA512

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSAAlgorithm.withSHA256andPKCS1Padding"))
        val RSAwithSHA256andPKCS1Padding get() = RSAAlgorithm.withSHA256andPKCS1Padding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSAAlgorithm.withSHA384andPKCS1Padding"))
        val RSAwithSHA384andPKCS1Padding get() = RSAAlgorithm.withSHA384andPKCS1Padding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSAAlgorithm.withSHA512andPKCS1Padding"))
        val RSAwithSHA512andPKCS1Padding get() = RSAAlgorithm.withSHA512andPKCS1Padding

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSAAlgorithm.withSHA256andPSSPadding"))
        val RSAwithSHA256andPSSPadding get() = RSAAlgorithm.withSHA256andPSSPadding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSAAlgorithm.withSHA384andPSSPadding"))
        val RSAwithSHA384andPSSPadding get() = RSAAlgorithm.withSHA384andPSSPadding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSAAlgorithm.withSHA512andPSSPadding"))
        val RSAwithSHA512andPSSPadding get() = RSAAlgorithm.withSHA512andPSSPadding

        override fun decodeFromTlv(element: X509AlgorithmIdentifier, der: Der) =
            ServiceLoader.load<SignatureAlgorithmsProvider>()
                .get(element, SignatureAlgorithmsProvider::getAlgorithm)

        @Deprecated("Use decodeFromTlv", replaceWith = ReplaceWith("decodeFromTlv(identifier)"))
        operator fun invoke(identifier: X509AlgorithmIdentifier): SignatureAlgorithm =
            decodeFromTlv(identifier)

    }
}

interface SpecializedSignatureAlgorithm : SpecializedDataIntegrityAlgorithm {
    override val algorithm: SignatureAlgorithm
}

interface SignatureAlgorithmsProvider {
    /** Parse a [SignatureAlgorithm] from its [X509AlgorithmIdentifier] form */
    fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier): SignatureAlgorithm?
}
