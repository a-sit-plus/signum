package at.asitplus.signum.supreme.sign

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.integrity.SignatureInputFormat
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

/**
 * Takes the leftmost bits of the byte array, and converts them to an unsigned `BigInteger`.
 *
 * (This matches the ECDSA spec.)
 */
internal fun SignatureInput.asECDSABigInteger(length: BitLength): BigInteger {
    val target = length.bytes.toInt()
    val dataIt = data.iterator()
    var resultBytes = if(dataIt.hasNext()) dataIt.next() else byteArrayOf()
    while (resultBytes.size < target) {
        if (dataIt.hasNext()) resultBytes += dataIt.next().also { require(it.isNotEmpty()) }
        else break
    }
    if (resultBytes.size > target)
        resultBytes = resultBytes.copyOfRange(0, target)
    require(resultBytes.size <= target)

    return BigInteger.fromByteArray(resultBytes, Sign.POSITIVE).let {
        if ((resultBytes.size == target) && (length.bitSpacing != 0u))
            it.shr(length.bitSpacing.toInt())
        else
            it
    }
}

internal val SignatureAlgorithm.preHashedSignatureFormat: SignatureInputFormat get() = when(this) {
    is SignatureAlgorithm.RSA -> this.digest
    is SignatureAlgorithm.ECDSA -> this.digest
    else -> throw UnsupportedCryptoException()
}
