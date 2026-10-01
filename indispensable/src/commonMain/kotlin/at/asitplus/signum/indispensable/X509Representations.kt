package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.awesn1.Asn1Exception

@Suppress("UNCHECKED_CAST")
val CryptoPrivateKey.asn1Representation: Pkcs8PrivateKeyInfo
    get() = representations[X509] as? Pkcs8PrivateKeyInfo
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

@Suppress("UNCHECKED_CAST")
val CryptoSignature.asn1Representation: X509SignatureValue
    get() = representations[X509] as? X509SignatureValue
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

@Suppress("UNCHECKED_CAST")
val SignatureValue.asn1Representation: X509SignatureValue
    get() = representations[X509] as? X509SignatureValue
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")


val CryptoPrivateKey.asPKCS8: Pkcs8PrivateKeyInfo get() = asn1Representation
