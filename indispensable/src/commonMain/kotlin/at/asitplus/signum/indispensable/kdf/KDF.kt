package at.asitplus.signum.indispensable.kdf

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.Indispensable
import at.asitplus.signum.indispensable.misc.BitLength


interface KDF {
    companion object {
        init { Indispensable.init() }
    }
}

// @Service
// TODO: do we need/want this? it only makes sense if we want to find KDFs by OID in the future or similar
interface KDFProvider {
}

// @Service
interface KDFOperationProvider {
    /** If the [KDF] in question is supported by this provider, perform it; otherwise, return null or throw */
    suspend fun deriveKey(kdf: KDF, salt: ByteArray, ikm: ByteArray, derivedKeyLength: BitLength): ByteArray?
}

/**
 * Derives a key using the specified [KDF] implementation.
 *
 * @param salt the salt to use
 * @param ikm the input key material
 * @param derivedKeyLength the length of the derived key
 */
suspend fun KDF.deriveKey(salt: ByteArray, ikm: ByteArray, derivedKeyLength: BitLength): ByteArray =
    ServiceLoader.load<KDFOperationProvider>().get(this) {
        deriveKey(it, salt, ikm, derivedKeyLength)
    }
