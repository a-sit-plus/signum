package at.asitplus.signum.indispensable.integrity

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.signum.Enumeration
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.Indispensable
import at.asitplus.signum.indispensable.sign.ECDSA as NewECDSA
import at.asitplus.signum.indispensable.sign.RSA as NewRSA

//for now, we just replicate the pattern, but since everything is sealed, we don't actually parse
interface SignatureAlgorithm : DataIntegrityAlgorithm, DerEncodable<X509AlgorithmIdentifier> {

    @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
        replaceWith = ReplaceWith("at.asitplus.signum.indispensable.sign.ECDSA"))
    typealias ECDSA = NewECDSA

    @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
        replaceWith = ReplaceWith("at.asitplus.signum.indispensable.sign.RSA"))
    typealias RSA = NewRSA

    companion object : Enumeration<SignatureAlgorithm> {
        init { Indispensable.init() }

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("ECDSA.withSHA256"))
        val ECDSAwithSHA256 get() = NewECDSA.withSHA256
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("ECDSA.withSHA384"))
        val ECDSAwithSHA384 get() = NewECDSA.withSHA384
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("ECDSA.withSHA512"))
        val ECDSAwithSHA512 get() = NewECDSA.withSHA512

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSA.withSHA256andPKCS1Padding"))
        val RSAwithSHA256andPKCS1Padding get() = NewRSA.withSHA256andPKCS1Padding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSA.withSHA384andPKCS1Padding"))
        val RSAwithSHA384andPKCS1Padding get() = NewRSA.withSHA384andPKCS1Padding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSA.withSHA512andPKCS1Padding"))
        val RSAwithSHA512andPKCS1Padding get() = NewRSA.withSHA512andPKCS1Padding

        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSA.withSHA256andPSSPadding"))
        val RSAwithSHA256andPSSPadding get() = NewRSA.withSHA256andPSSPadding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSA.withSHA384andPSSPadding"))
        val RSAwithSHA384andPSSPadding get() = NewRSA.withSHA384andPSSPadding
        @Deprecated(message = "Concrete algorithms migrated out of SignatureAlgorithm as part of providerization",
            replaceWith = ReplaceWith("RSA.withSHA512andPSSPadding"))
        val RSAwithSHA512andPSSPadding get() = NewRSA.withSHA512andPSSPadding

        override val entries: Iterable<SignatureAlgorithm> get() =
            ServiceLoader.load<SignatureAlgorithmsProvider>()
                .flatMap(SignatureAlgorithmsProvider::getAlgorithms)

        operator fun invoke(identifier: X509AlgorithmIdentifier): SignatureAlgorithm =
            ServiceLoader.load<SignatureAlgorithmsProvider>()
                .get(identifier, SignatureAlgorithmsProvider::getAlgorithm)

    }
}

interface SpecializedSignatureAlgorithm : SpecializedDataIntegrityAlgorithm {
    override val algorithm: SignatureAlgorithm
}

interface SignatureAlgorithmsProvider {
    /** A best-effort attempt at a list of algorithms supported by this provider. May be incomplete for, e.g., parametrized algorithms. */
    fun getAlgorithms() : Iterable<SignatureAlgorithm>
    /** Parse a [SignatureAlgorithm] from its [X509AlgorithmIdentifier] form */
    fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier): SignatureAlgorithm?
}
