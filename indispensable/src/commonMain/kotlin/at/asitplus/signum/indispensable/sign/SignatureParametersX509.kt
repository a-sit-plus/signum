package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.signum.indispensable.sign.RsaAlgorithm.Parameters.PssPadded

@Suppress("UNCHECKED_CAST")
val <T : RsaParams> RsaAlgorithm.Parameters<T>.asn1Representation: T
    get() = representations[X509] as? T
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

@Suppress("UNCHECKED_CAST")
val RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.asn1Representation: X509AlgorithmIdentifier
    get() = representations[X509] as? X509AlgorithmIdentifier
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

@Suppress("UNCHECKED_CAST")
val RsaPrivateKey.PrimeInfo.asn1Representation: Pkcs1RsaOtherPrimeInfo
    get() = representations[X509] as? Pkcs1RsaOtherPrimeInfo
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")


val RsaPrivateKey.asPKCS1: Pkcs1RsaPrivateKeyInfo get() = pkcs1Representation
val EcdsaPrivateKey.asSEC1: Sec1EcPrivateKeyInfo get() = sec1Representation
