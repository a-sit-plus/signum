package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.Version
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.Der
import at.asitplus.catching
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import kotlinx.serialization.KSerializer

/** PKCS#8 representation of a private key. Equality checks remain based on cryptographic Signum properties. */
interface CryptoPrivateKey : DerPemEncodable<Pkcs8PrivateKeyInfo>, Identifiable {

    interface WithPublicKey : CryptoPrivateKey {
        val publicKey: CryptoPublicKey
    }

    val attributes: Set<Asn1Element>?

    val asPKCS8: DerPemEncodable<Pkcs8PrivateKeyInfo> get() = this

    override val pemLabel: String get() = Companion.canonicalPemLabel

    companion object : DerPemDecodable<Pkcs8PrivateKeyInfo, CryptoPrivateKey> {
        init { Indispensable.init() }
        override val canonicalPemLabel: String get() = Pkcs8PrivateKeyInfo.canonicalPemLabel
        override val alternativePemLabels: Set<String> get() = Pkcs8PrivateKeyInfo.alternativePemLabels
        override fun decodeFromTlv(
            element: Pkcs8PrivateKeyInfo,
            der: Der,
        ): CryptoPrivateKey =
            ServiceLoader.load<PrivateKeyFormatProvider>()
                .get(element, PrivateKeyFormatProvider::decodeFromAsn1)

        override fun decodeFromPemBlockPayload(
            serializer: KSerializer<Pkcs8PrivateKeyInfo>,
            src: PemBlock,
            limit: Long,
            der: Der,
        ): CryptoPrivateKey =
            when (src.pemLabel) {
                Pkcs1RsaPrivateKeyInfo.PEM_LABEL -> RSAPrivateKey.FromPKCS1.decodeFromDer(src.payload, der)
                Sec1EcPrivateKeyInfo.PEM_LABEL -> ECDSAPrivateKey.FromSEC1.decodeFromDer(src.payload, der)
                Pkcs8PrivateKeyInfo.PEM_LABEL_PRIVATE_KEY -> decodeFromDer(serializer, src.payload, limit, der)
                else -> error("Label ${src.pemLabel} for private key is invalid")
            }

        fun fromIosEncoded(keyBytes: ByteArray): KmmResult<CryptoPrivateKey.WithPublicKey> = catching {
            // TODO: providerize cleanly & move to iOS
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) {
                ECDSAPrivateKey.iosDecodeInternal(keyBytes)
            } else {
                RSAPrivateKey.FromPKCS1.decodeFromTlv(Asn1Element.parse(keyBytes)) as CryptoPrivateKey.WithPublicKey
            }
        }
    }

    @Deprecated(message = "Private key types migrated out of CryptoPrivateKey as part of providerization",
        replaceWith = ReplaceWith("ECDSAPrivateKey"))
    typealias EC = ECDSAPrivateKey
    @Deprecated(message = "Private key types migrated out of CryptoPrivateKey as part of providerization",
        replaceWith = ReplaceWith("RSAPrivateKey"))
    typealias RSA = RSAPrivateKey
}

// @Service
interface PrivateKeyFormatProvider {
    fun decodeFromAsn1(element: Pkcs8PrivateKeyInfo): CryptoPrivateKey?
}
