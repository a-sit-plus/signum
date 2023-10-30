package at.asitplus.crypto.datatypes.cose

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.asn1.decodeFromDer

/**
 * Wrapper to handle parameters for different COSE public key types.
 */
sealed class CoseKeyParams() {

    abstract fun toCryptoPublicKey(): CryptoPublicKey?

    /**
     * COSE EC public key parameters **without point compression**, i.e. the y coordinate being a ByteArray.
     * Since this is used as part of a COSE-specific DTO, every property is nullable
     */
    data class EcYByteArrayParams(
        val curve: CoseEllipticCurve? = null,
        val x: ByteArray? = null,
        val y: ByteArray? = null,
        val d: ByteArray? = null
    ) : CoseKeyParams() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EcYByteArrayParams

            if (curve != other.curve) return false
            if (x != null) {
                if (other.x == null) return false
                if (!x.contentEquals(other.x)) return false
            } else if (other.x != null) return false
            if (y != null) {
                if (other.y == null) return false
                if (!y.contentEquals(other.y)) return false
            } else if (other.y != null) return false
            if (d != null) {
                if (other.d == null) return false
                if (!d.contentEquals(other.d)) return false
            } else if (other.d != null) return false

            return true
        }

        override fun hashCode(): Int {
            var result = curve?.hashCode() ?: 0
            result = 31 * result + (x?.contentHashCode() ?: 0)
            result = 31 * result + (y?.contentHashCode() ?: 0)
            result = 31 * result + (d?.contentHashCode() ?: 0)
            return result
        }

        override fun toCryptoPublicKey(): CryptoPublicKey? {
            return CryptoPublicKey.Ec.fromCoordinates(
                curve = curve?.toJwkCurve() ?: return null,
                x = x ?: return null,
                y = y ?: return null
            )
        }
    }


    /*
    //TODO Implements elliptic curve public key parameters in case of y being a bool value
    data class EcYBoolParams(
        val curve: CoseEllipticCurve? = null,
        val x: ByteArray? = null,
        val y: Boolean? = null,
        val d: ByteArray? = null
    ) : CoseKeyParams() {

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EcYBoolParams

            if (curve != other.curve) return false
            if (x != null) {
                if (other.x == null) return false
                if (!x.contentEquals(other.x)) return false
            } else if (other.x != null) return false
            if (y != other.y) return false
            if (d != null) {
                if (other.d == null) return false
                if (!d.contentEquals(other.d)) return false
            } else if (other.d != null) return false

            return true
        }

        override fun hashCode(): Int {
            var result = curve?.hashCode() ?: 0
            result = 31 * result + (x?.contentHashCode() ?: 0)
            result = 31 * result + (y?.hashCode() ?: 0)
            result = 31 * result + (d?.contentHashCode() ?: 0)
            return result
        }

        override fun toCryptoPublicKey(): CryptoPublicKey? = TODO()

    //        TODO conversion to cryptoPublicKey (needs de-/compression of Y coordinate)
    */

    /**
     * COSE RSA public key params. Since this is used as part of a COSE-specific DTO, every property is nullable
     */
    data class RsaParams(
        val n: ByteArray? = null,
        val e: ByteArray? = null,
        val d: ByteArray? = null
    ) : CoseKeyParams() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as RsaParams

            if (n != null) {
                if (other.n == null) return false
                if (!n.contentEquals(other.n)) return false
            } else if (other.n != null) return false
            if (e != null) {
                if (other.e == null) return false
                if (!e.contentEquals(other.e)) return false
            } else if (other.e != null) return false
            if (d != null) {
                if (other.d == null) return false
                if (!d.contentEquals(other.d)) return false
            } else if (other.d != null) return false

            return true
        }

        override fun hashCode(): Int {
            var result = n?.contentHashCode() ?: 0
            result = 31 * result + (e?.contentHashCode() ?: 0)
            result = 31 * result + (d?.contentHashCode() ?: 0)
            return result
        }

        override fun toCryptoPublicKey(): CryptoPublicKey? {
            return let {
                CryptoPublicKey.Rsa(
                    n = n ?: return null,
                    e = e?.let { bytes -> Int.decodeFromDer(bytes) } ?: return null
                )
            }
        }
    }
}