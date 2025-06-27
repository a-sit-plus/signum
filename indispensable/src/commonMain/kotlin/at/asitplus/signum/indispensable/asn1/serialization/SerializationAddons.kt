package at.asitplus.signum.indispensable.asn1.serialization


import at.asitplus.signum.indispensable.CryptoPrivateKey
import kotlinx.serialization.ExperimentalSerializationApi

@ExperimentalSerializationApi
fun DER.encodeToDer(value:  CryptoPrivateKey.WithPublicKey<*>) = encodeToDer(CryptoPrivateKey.Companion, value)

//TODO more shadowing