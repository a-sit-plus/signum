package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPrivateKey
import at.asitplus.signum.indispensable.sign.fromAsn1

/** PKCS#8 representation of a private key. Equality checks remain based on cryptographic Signum properties. */
interface PrivateKey : WithSourceRepresentation {

    interface WithPublicKey : PrivateKey {
        val publicKey: PublicKey
    }

    @SignumInternals
    class Unknown(
        lookupResult: UnsupportedCryptoException
    ) : PrivateKey, ServiceLoader.UnknownShim(lookupResult)

    companion object {
        init { Signum.installIndispensable() }
        @Deprecated("Use SecKeyRef.toPrivateKey instead")
        fun fromIosEncoded(keyBytes: ByteArray): PrivateKey.WithPublicKey =
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) {
                EcdsaPrivateKey.iosDecodeInternal(keyBytes)
            } else {
                RsaPrivateKey.fromAsn1.PKCS1(keyBytes)
            }

    }

    @Deprecated(message = "Private key types migrated out of PrivateKey as part of providerization",
        replaceWith = ReplaceWith("EcdsaPrivateKey"))
    typealias EC = EcdsaPrivateKey
    @Deprecated(message = "Private key types migrated out of PrivateKey as part of providerization",
        replaceWith = ReplaceWith("RsaPrivateKey"))
    typealias RSA = RsaPrivateKey
}

// @Service
interface Asn1PrivateKeyFormatProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: PrivateKey): Pkcs8PrivateKeyInfo? = null

    fun decodeFromAsn1(privateKeyInfo: Pkcs8PrivateKeyInfo): PrivateKey?
}

@Deprecated("Renamed to PrivateKey", ReplaceWith("PrivateKey", "at.asitplus.signum.indispensable.PrivateKey"))
typealias CryptoPrivateKey = PrivateKey
