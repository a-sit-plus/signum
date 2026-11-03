package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPrivateKey
import at.asitplus.signum.indispensable.sign.fromAsn1Representation

/** PKCS#8 representation of a private key. Equality checks remain based on cryptographic Signum properties. */
interface CryptoPrivateKey : Encodable {

    interface WithPublicKey : CryptoPrivateKey {
        val publicKey: CryptoPublicKey
    }

    val attributes: Set<Asn1Element>? get() = asn1Representation.attributes

    @OptIn(SignumInternals::class)
    private class Unknown(
        override val asn1Representation: Pkcs8PrivateKeyInfo,
        override val lookupResult: UnsupportedCryptoException
    ) : CryptoPrivateKey, ServiceLoader.UnknownShim {
        override fun toString() = "Unknown CryptoPrivateKey ($asn1Representation)"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Unknown) return false
            return asn1Representation == other.asn1Representation
        }
        override fun hashCode() = asn1Representation.hashCode()
    }

                .getWithUnknown(element, ::Unknown, PrivateKeyFormatProvider::decodeFromAsn1)

    companion object : Decodable<CryptoPrivateKey> {
        init { Signum.installIndispensable() }
        @Deprecated("Use SecKeyRef.toCryptoPrivateKey instead")
        fun fromIosEncoded(keyBytes: ByteArray): CryptoPrivateKey.WithPublicKey =
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) {
                EcdsaPrivateKey.iosDecodeInternal(keyBytes)
            } else {
                RsaPrivateKey.fromAsn1Representation(Signum.Der.decodeFromByteArray(Pkcs1RsaPrivateKeyInfo.serializer(), keyBytes))
            }

    }

    @Deprecated(message = "Private key types migrated out of CryptoPrivateKey as part of providerization",
        replaceWith = ReplaceWith("EcdsaPrivateKey"))
    typealias EC = EcdsaPrivateKey
    @Deprecated(message = "Private key types migrated out of CryptoPrivateKey as part of providerization",
        replaceWith = ReplaceWith("RsaPrivateKey"))
    typealias RSA = RsaPrivateKey
}

// @Service
interface PrivateKeyFormatProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: CryptoPrivateKey): Pkcs8PrivateKeyInfo? = null

    fun decodeFromAsn1(privateKeyInfo: Pkcs8PrivateKeyInfo): CryptoPrivateKey?
}
