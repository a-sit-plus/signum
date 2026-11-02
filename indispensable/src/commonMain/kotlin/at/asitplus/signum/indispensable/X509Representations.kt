package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.Signum

val PrivateKey.asn1Representation: Pkcs8PrivateKeyInfo
    get() = sourceRepresentationFor(X509) as? Pkcs8PrivateKeyInfo ?: run {
        Signum.installIndispensable()
        Signum.load<PrivateKeyFormatProvider>().get(this, PrivateKeyFormatProvider::encodeToAsn1)
    }

val Signature.asn1Representation: X509SignatureValue
    get() = sourceRepresentationFor(X509) as? X509SignatureValue ?: run {
        Signum.installIndispensable()
        Signum.load<SignatureFormatProvider>().get(this, SignatureFormatProvider::encodeToAsn1)
    }

val SignatureValue.asn1Representation: X509SignatureValue
    get() = sourceRepresentationFor(X509) as? X509SignatureValue
        ?: model

val PrivateKey.asPKCS8: Pkcs8PrivateKeyInfo get() = asn1Representation
