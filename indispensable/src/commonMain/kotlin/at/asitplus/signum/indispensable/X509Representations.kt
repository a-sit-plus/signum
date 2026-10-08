package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.Signum
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.signum.indispensable.sign.*

val CryptoPrivateKey.asn1Representation: Pkcs8PrivateKeyInfo
    get() = sourceRepresentationFor(X509) as? Pkcs8PrivateKeyInfo ?: run {
        Signum.installIndispensable()
        Signum.load<PrivateKeyFormatProvider>().get(this, PrivateKeyFormatProvider::encodeToAsn1)
    }

val CryptoSignature.asn1Representation: X509SignatureValue
    get() = sourceRepresentationFor(X509) as? X509SignatureValue ?: run {
        Signum.installIndispensable()
        Signum.load<SignatureFormatProvider>().get(this, SignatureFormatProvider::encodeToAsn1)
    }

val SignatureValue.asn1Representation: X509SignatureValue
    get() = sourceRepresentationFor(X509) as? X509SignatureValue
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

val CryptoPrivateKey.asPKCS8: Pkcs8PrivateKeyInfo get() = asn1Representation
