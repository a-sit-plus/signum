package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPrivateKey
import at.asitplus.signum.indispensable.sign.fromAsn1Representation

/** PKCS#8 representation of a private key. Equality checks remain based on cryptographic Signum properties. */
interface PrivateKey : Encodable {

    interface WithPublicKey : PrivateKey {
        val publicKey: PublicKey
    }

    val attributes: Set<Asn1Element>? get() = asn1Representation.attributes

    companion object : Decodable<PrivateKey> {
        init { Signum.installIndispensable() }

        fun fromAsn1Representation(
            element: Pkcs8PrivateKeyInfo): PrivateKey =
            Signum.load<PrivateKeyFormatProvider>()
                .get(element, PrivateKeyFormatProvider::decodeFromAsn1)

        @Deprecated("Use SecKeyRef.toCryptoPrivateKey instead")
        fun fromIosEncoded(keyBytes: ByteArray): PrivateKey.WithPublicKey =
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) {
                EcdsaPrivateKey.iosDecodeInternal(keyBytes)
            } else {
                RsaPrivateKey.fromAsn1Representation(Signum.Der.decodeFromByteArray(Pkcs1RsaPrivateKeyInfo.serializer(), keyBytes))
            }

    }

    @Deprecated(message = "Private key types migrated out of CryptoPrivateKey as part of providerization",
        replaceWith = ReplaceWith("EcdsaPrivateKey", "at.asitplus.signum.indispensable.sign.EcdsaPrivateKey"))
    typealias EC = EcdsaPrivateKey
    @Deprecated(message = "Private key types migrated out of CryptoPrivateKey as part of providerization",
        replaceWith = ReplaceWith("RsaPrivateKey", "at.asitplus.signum.indispensable.sign.RsaPrivateKey"))
    typealias RSA = RsaPrivateKey
}

// @Service
interface PrivateKeyFormatProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: PrivateKey): Pkcs8PrivateKeyInfo? = null

    fun decodeFromAsn1(privateKeyInfo: Pkcs8PrivateKeyInfo): PrivateKey?
}

@Deprecated("Renamed to PrivateKey", ReplaceWith("PrivateKey", "at.asitplus.signum.indispensable.PrivateKey"))
typealias CryptoPrivateKey = PrivateKey
