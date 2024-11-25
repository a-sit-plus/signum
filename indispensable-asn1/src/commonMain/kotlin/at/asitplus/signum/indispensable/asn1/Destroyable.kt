package at.asitplus.signum.indispensable.asn1

/**
 * Indicates that information in the implementing class can be destroyed. Useful for secrets (private keys, symmetric keys, …)
 * [Asn1Integer] implements this interface, making it possible to store secret information that can later be destroyed.
 */
interface Destroyable {
    fun destroy()

    fun isDestroyed(): Boolean

}

/**
 * Zeroes out all bytes contained in this array, effectively destroying all information contained in it, except for the length.
 */
fun ByteArray.destroy() = fill(0)