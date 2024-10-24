package at.asitplus.signum.ecmath

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECPoint
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.supreme.hash.digest
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import org.kotlincrypto.SecureRandom
import kotlin.experimental.xor
import kotlin.jvm.JvmInline

private typealias hash_to_field = (Sequence<ByteArray>, Int) -> Array<ModularBigInteger>
private typealias map_to_curve = (ModularBigInteger) -> ECPoint
private typealias clear_cofactor = (ECPoint) -> ECPoint

/** RFC 9380 8.2ff */
private inline val ECCurve.Z get() = BigInteger(when (this) {
    ECCurve.SECP_256_R_1 -> -10
    ECCurve.SECP_384_R_1 -> -12
    ECCurve.SECP_521_R_1 -> -4
}).toModularBigInteger(this.modulus)

private inline fun ModularBigInteger.sqrt() =
    pow(modulus.plus(1).div(4))

private inline val ECCurve.c1 get() = this.modulus.minus(3).div(4)
private inline val ECCurve.c2 get() = (-Z).sqrt()

/** log(modulus) * (3/2), this matches RFC9380 NIST curve suites, and also matches RFC9497 */
private inline val ECCurve.L get() = when(this) {
    ECCurve.SECP_256_R_1 -> 48
    ECCurve.SECP_384_R_1 -> 72
    ECCurve.SECP_521_R_1 -> 98
}

/** per RFC9794 4.7.2. */
fun ECCurve.randomScalar() = SecureRandom().nextBytesOf(this.L).let { BigInteger.fromByteArray(it, Sign.POSITIVE).toModularBigInteger(this.order) }

private inline fun clear_cofactor_trivial(p: ECPoint) = p.curve.cofactor * p

private typealias expand_message = (msg: Sequence<ByteArray>, domain: ByteArray, lenInBytes: Int) -> Buffer

private infix fun ByteArray.xor(other: ByteArray): ByteArray {
    check(this.size == other.size)
    return ByteArray(this.size) { i -> this[i] xor other[i] }
}

private inline fun I2OSP(value: Int, len: Int): ByteArray {
    check(len == 2)
    require(value in 0..0xffff)
    return byteArrayOf(((value shr 8) and 0xff).toByte(), (value and 0xff).toByte())
}

private inline fun expand_message_xmd(digest: Digest): (msg: Sequence<ByteArray>, domain: ByteArray, lenInBytes: Int) -> Buffer {
    check(digest.outputLength.bitSpacing == 0u) { "RFC9380 requirement: b mod 8 = 0 " }
    check(digest.outputLength <= digest.inputBlockSize) { "RFC9380 requirement: b <= s" }
    val sInBytes = digest.inputBlockSize.bytes.toInt()
    val bInBytes = digest.outputLength.bytes.toInt()
    return { msg, domain, lenInBytes ->
        val ell = (lenInBytes.floorDiv(bInBytes) + if (lenInBytes.mod(bInBytes) != 0) 1 else 0).also {
            require (it <= 255) { "RFC 9380 requirement: ell <= 255"}
        }.toUByte()
        require(lenInBytes <= 65535 && domain.size <= 255) { "RFC 9380 requirements" }
        val DST_prime = domain + domain.size.toByte()
        val Z_pad = ByteArray(sInBytes)
        val l_i_b_str = I2OSP(lenInBytes, 2)
        val msg_prime = sequenceOf(Z_pad) + msg + sequenceOf(l_i_b_str, byteArrayOf(0x00), DST_prime)
        val b0 = digest.digest(msg_prime)
        val result = Buffer()
        var H = ByteArray(bInBytes)
        for (i in 1.toUByte()..ell) {
            H = digest.digest(sequenceOf(b0 xor H, byteArrayOf(i.toByte()), DST_prime))
            result.write(H)
        }
        /* return */ result
    }
}

/** this only works for prime field curves (m = 1) */
private inline fun hash_to_field_rfc9380(crossinline em: expand_message, curve: ECCurve, domain: ByteArray)
        : (msg: Sequence<ByteArray>, count: Int) -> Array<ModularBigInteger>
{
    val p = curve.modulus
    val L = curve.L
    return { msg: Sequence<ByteArray>, count: Int ->
        val lenInBytes = count * L
        val uniformBytes = em(msg, domain, lenInBytes)
        /* return */ Array(count) {
            val tv = uniformBytes.readByteArray(L)
            BigInteger.fromByteArray(tv, Sign.POSITIVE).toModularBigInteger(p)
        }
    }
}

private inline fun sgn0(a: ModularBigInteger): Int = a.toBigInteger().mod(BigInteger.TWO).intValue()
/** this is appendix F.2.1.2. */
private inline fun ECCurve.sqrt_ratio_3mod4(u: ModularBigInteger, v: ModularBigInteger): Pair<Boolean, ModularBigInteger> {
    var tv1: ModularBigInteger; var tv2: ModularBigInteger; var tv3: ModularBigInteger;
    var y1: ModularBigInteger;  val y2: ModularBigInteger; val y: ModularBigInteger
    tv1 = v*v
    tv2 = u*v
    tv1 = tv1*tv2
    y1 = tv1.pow(c1)
    y1 = y1 * tv2
    y2 = y1 * c2
    tv3 = y1*y1
    tv3 = tv3*v
    val isQR = (tv3 == u)
    y = CMOV(y2, y1, isQR)
    return Pair(isQR, y)
}

/** this only works for weierstrass curves with A != 0, B != 0; taken from RFC9380 appendix F.2  */
private inline fun map_to_curve_simple_swu(curve: ECCurve)
        : (u: ModularBigInteger) -> ECPoint
{
    val Z = curve.Z
    val A = curve.a
    val B = curve.b
    return { u: ModularBigInteger ->
        var tv1: ModularBigInteger; var tv2: ModularBigInteger; var tv3: ModularBigInteger
        var tv4: ModularBigInteger; var tv5: ModularBigInteger; var tv6: ModularBigInteger
        var x: ModularBigInteger; var y: ModularBigInteger
/*  1.*/tv1 = u*u
/*  2.*/tv1 = Z * tv1
/*  3.*/tv2 = tv1*tv1
/*  4.*/tv2 = tv2+tv1
/*  5.*/tv3 = tv2+1
/*  6.*/tv3 = B * tv3
/*  7.*/tv4 = CMOV(Z, -tv2, !tv2.isZero())
/*  8.*/tv4 = A * tv4
/*  9.*/tv2 = tv3*tv3
/* 10.*/tv6 = tv4*tv4
/* 11.*/tv5 = A * tv6
/* 12.*/tv2 = tv2 + tv5
/* 13.*/tv2 = tv2 * tv3
/* 14.*/tv6 = tv6 * tv4
/* 15.*/tv5 = B * tv6
/* 16.*/tv2 = tv2 + tv5
/* 17.*/  x = tv1 * tv3
/* 18.*/val (isGx1Square, y1) = curve.sqrt_ratio_3mod4(tv2, tv6)
/* 19.*/  y = tv1 * u
/* 20.*/  y = y * y1
/* 21.*/  x = CMOV(x, tv3, isGx1Square)
/* 22.*/  y = CMOV(y, y1, isGx1Square)
/* 23.*/val e1 = sgn0(u) == sgn0(y)
/* 24.*/  y = CMOV(-y, y, e1)
/* 25.*/  x = x / tv4
        /* return */ ECPoint.fromXY(curve, x, y)
    }
}

private inline fun encode_to_curve
            (crossinline htf: hash_to_field, crossinline mtc: map_to_curve, crossinline ccf: clear_cofactor) =
HashToEllipticCurve { msg: Sequence<ByteArray> ->
    val u = htf(msg, 1)
    val Q = mtc(u[0])
    val P = ccf(Q)
    /*return*/ P
}

private inline fun hash_to_curve
            (crossinline htf: hash_to_field, crossinline mtc: map_to_curve, crossinline ccf: clear_cofactor) =
HashToEllipticCurve { msg: Sequence<ByteArray> ->
    val u = htf(msg, 2)
    val Q0 = mtc(u[0])
    val Q1 = mtc(u[1])
    val R = Q0 + Q1
    val P = ccf(R)
    /*return*/ P
}

private inline fun <T> CMOV(a: T, b: T, c: Boolean) = if (c) b else a

@JvmInline
value class HashToEllipticCurve(private val fn: (Sequence<ByteArray>)->ECPoint) {
    operator fun invoke(data: Sequence<ByteArray>) = fn(data)
    operator fun invoke(data: ByteArray) = fn(sequenceOf(data))
    operator fun invoke(data: Iterable<ByteArray>) = fn(data.asSequence())
}

object RFC9380 {
    fun `P256_XMD∶SHA-256_SSWU_RO_`(domain: ByteArray) =
        hash_to_curve(
            hash_to_field_rfc9380(expand_message_xmd(Digest.SHA256), ECCurve.SECP_256_R_1, domain),
            map_to_curve_simple_swu(ECCurve.SECP_256_R_1),
            ::clear_cofactor_trivial)
    fun `P256_XMD∶SHA-256_SSWU_NU_`(domain: ByteArray) =
        encode_to_curve(
            hash_to_field_rfc9380(expand_message_xmd(Digest.SHA256), ECCurve.SECP_256_R_1, domain),
            map_to_curve_simple_swu(ECCurve.SECP_256_R_1),
            ::clear_cofactor_trivial)
    fun `P384_XMD∶SHA-384_SSWU_RO_`(domain: ByteArray) =
        hash_to_curve(
            hash_to_field_rfc9380(expand_message_xmd(Digest.SHA384), ECCurve.SECP_384_R_1, domain),
            map_to_curve_simple_swu(ECCurve.SECP_384_R_1),
            ::clear_cofactor_trivial)
    fun `P384_XMD∶SHA-384_SSWU_NU_`(domain: ByteArray) =
        encode_to_curve(
            hash_to_field_rfc9380(expand_message_xmd(Digest.SHA384), ECCurve.SECP_384_R_1, domain),
            map_to_curve_simple_swu(ECCurve.SECP_384_R_1),
            ::clear_cofactor_trivial)
    fun `P521_XMD∶SHA-512_SSWU_RO_`(domain: ByteArray) =
        hash_to_curve(
            hash_to_field_rfc9380(expand_message_xmd(Digest.SHA512), ECCurve.SECP_521_R_1, domain),
            map_to_curve_simple_swu(ECCurve.SECP_521_R_1),
            ::clear_cofactor_trivial)
    fun `P521_XMD∶SHA-512_SSWU_NU_`(domain: ByteArray) =
        encode_to_curve(
            hash_to_field_rfc9380(expand_message_xmd(Digest.SHA512), ECCurve.SECP_521_R_1, domain),
            map_to_curve_simple_swu(ECCurve.SECP_521_R_1),
            ::clear_cofactor_trivial)
}

