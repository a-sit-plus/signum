package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.signum.indispensable.sign.*

val CryptoPrivateKey.asn1Representation: Pkcs8PrivateKeyInfo
    get() = representations[X509] as? Pkcs8PrivateKeyInfo ?: when (this) {
        is RsaPrivateKey -> Pkcs8PrivateKeyInfo.Companion(asPKCS1, attributes)
        is EcdsaPrivateKey -> Pkcs8PrivateKeyInfo.Companion(asSEC1, curveOidForPkcs8(), attributes)
        else -> throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")
    }

val CryptoSignature.asn1Representation: X509SignatureValue
    get() = representations[X509] as? X509SignatureValue ?: when (this) {
        is EcdsaSignature -> EcdsaSigValue(r.toAsn1Integer(), s.toAsn1Integer()).toX509SignatureValue()
        is RsaSignature -> X509SignatureValue(rawBytes)
        else -> throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")
    }

val SignatureValue.asn1Representation: X509SignatureValue
    get() = representations[X509] as? X509SignatureValue
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

val CryptoPrivateKey.asPKCS8: Pkcs8PrivateKeyInfo get() = asn1Representation
