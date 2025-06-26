package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.CryptoPrivateKey
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.serializer

@ExperimentalSerializationApi
inline fun encodeToDer(value: CryptoPrivateKey.WithPublicKey<*>) = encodeToAsn1Bytes(CryptoPrivateKey.Companion, value)