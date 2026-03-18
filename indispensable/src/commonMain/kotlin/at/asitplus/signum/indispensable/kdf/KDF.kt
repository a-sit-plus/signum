package at.asitplus.signum.indispensable.kdf

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.integrity.HMAC
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.internals.*


interface KDF: Enumerable {
    companion object : Enumeration<KDF> {
        override val entries: Iterable<KDF> get() =
            ServiceLoader.load<KDFProvider>().asSequence().flatMap(KDFProvider::getKDFs).toList()
    }
}

// @Service
// TODO: do we need/want this? it only makes sense if we want to find KDFs by OID in the future or similar
interface KDFProvider {
    /** The list of KDFs supported by this provider */
    fun getKDFs(): Iterable<KDF>
}

// @Service
interface KDFOperationProvider {
    /** If the Digest in question is supported by this provider, return the operator to use; otherwise, return null */
    fun getKDFOperator(kdf: KDF): (suspend (salt: ByteArray, ikm: ByteArray, derivedKeyLength: BitLength) -> ByteArray)?
}

/**
 * Derives a key using the specified [KDF] implementation.
 *
 * @param salt the salt to use
 * @param ikm the input key material
 * @param derivedKeyLength the length of the derived key
 */
suspend fun KDF.deriveKey(salt: ByteArray, ikm: ByteArray, derivedKeyLength: BitLength): KmmResult<ByteArray> = catching {
    (ServiceLoader.load<KDFOperationProvider>().also {
        if (it.none()) throw UnsupportedCryptoException("No KDF derivation providers are loaded")
    }.firstNotNullOfOrNull {
        it.getKDFOperator(this@deriveKey)
    } ?: throw UnsupportedCryptoException("No loaded KDF derivation provider supports ${this@deriveKey}"))
        .invoke(salt, ikm, derivedKeyLength)
}
