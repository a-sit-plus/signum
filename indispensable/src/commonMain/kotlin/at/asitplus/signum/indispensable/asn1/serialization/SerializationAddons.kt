package at.asitplus.signum.indispensable.asn1.serialization


import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import kotlinx.serialization.ExperimentalSerializationApi

@ExperimentalSerializationApi
fun DER.encodeToDer(value: CryptoPrivateKey.WithPublicKey<*>) = encodeToDer(CryptoPrivateKey.Companion, value)

@ExperimentalSerializationApi
fun DER.encodeToTlv(value: CryptoPrivateKey.WithPublicKey<*>) = encodeToTlv(CryptoPrivateKey.Companion, value)

@ExperimentalSerializationApi
fun <T : CryptoPrivateKey.WithPublicKey<*>> DER.decodeFromTlv(source: Asn1Element): CryptoPrivateKey.WithPublicKey<*> =
    CryptoPrivateKey.decodeFromTlv(source as Asn1Sequence) as CryptoPrivateKey.WithPublicKey<*>

@ExperimentalSerializationApi
fun <T : CryptoPrivateKey.WithPublicKey<*>> DER.decodeFromDer(source: ByteArray): CryptoPrivateKey.WithPublicKey<*> =
    CryptoPrivateKey.decodeFromDer(source) as CryptoPrivateKey.WithPublicKey<*>


//TODO more shadowing