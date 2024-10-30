package at.asitplus.signum.ecmath

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECPoint
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.hash.digest
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import org.kotlincrypto.SecureRandom
import kotlin.experimental.xor
import kotlin.jvm.JvmInline

private typealias HashToFieldFn = (msg: Sequence<ByteArray>, count: Int) -> Array<ModularBigInteger>
private typealias MapToCurveFn = (ModularBigInteger) -> ECPoint
private typealias ClearCofactorFn = (ECPoint) -> ECPoint
private typealias ExpandMessageFn = (msg: Sequence<ByteArray>, domain: ByteArray, lenInBytes: Int) -> Buffer

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

/** log2(modulus) * (3/2), this matches RFC9380 NIST curve suites, and also matches RFC9497 */
private inline val ECCurve.L get() = when(this) {
    ECCurve.SECP_256_R_1 -> 48
    ECCurve.SECP_384_R_1 -> 72
    ECCurve.SECP_521_R_1 -> 98
}

/** per RFC9794 4.7.2. */
fun ECCurve.randomScalar() = SecureRandom().nextBytesOf(this.L).let { BigInteger.fromByteArray(it, Sign.POSITIVE).toModularBigInteger(this.order) }

private inline fun clearCofactorTrivial(p: ECPoint) = p.curve.cofactor * p

private infix fun ByteArray.xor(other: ByteArray): ByteArray {
    check(this.size == other.size)
    return ByteArray(this.size) { i -> this[i] xor other[i] }
}

/** I2OSP (Integer To Octet String Primitive) for case len = 1 only */
private inline fun i2ospForLen1(value: Byte): ByteArray = byteArrayOf(value)

/** I2OSP (Integer To Octet String Primitive) for case len = 1 only */
private inline fun i2ospForLen1(value: Int): ByteArray {
    require (value in 0..0xff)
    return i2ospForLen1((value and 0xff).toByte())
}

/** I2OSP (Integer To Octet String Primitive) for case len = 2 only */
private inline fun i2ospForLen2(value: Int): ByteArray {
    require(value in 0..0xffff)
    return byteArrayOf(((value shr 8) and 0xff).toByte(), (value and 0xff).toByte())
}

/** RFC9380: expand_message_xmd */
private inline fun expandMessageXMD(digest: Digest): ExpandMessageFn {
    check(digest.outputLength.bitSpacing == 0u) { "RFC9380 requirement: b mod 8 = 0 " }
    check(digest.outputLength <= digest.inputBlockSize) { "RFC9380 requirement: b <= s" }
    val sInBytes = digest.inputBlockSize.bytes.toInt()
    val bInBytes = digest.outputLength.bytes.toInt()
    return { msg, domain, lenInBytes ->
        val ell = (lenInBytes.floorDiv(bInBytes) + if (lenInBytes.mod(bInBytes) != 0) 1 else 0).also {
            require (it <= 255) { "RFC 9380 requirement: ell <= 255"}
        }.toUByte()
        require(lenInBytes <= 65535) { "RFC 9380 requirement: len_in_bytes <= 65535" }
        require(domain.size <= 255) { "RFC 9380 requirement: len(DST) <= 255" }
        val domainPrime = domain + i2ospForLen1(domain.size)
        val zeroPad = ByteArray(sInBytes)
        val lenInBytesStr = i2ospForLen2(lenInBytes)
        val msgPrime = sequenceOf(zeroPad) + msg + sequenceOf(lenInBytesStr, i2ospForLen1(0x00), domainPrime)
        val b0 = digest.digest(msgPrime)
        val result = Buffer()
        var H = ByteArray(bInBytes)
        for (i in 1.toUByte()..ell) {
            H = digest.digest(sequenceOf(b0 xor H, i2ospForLen1(i.toByte()), domainPrime))
            result.write(H)
        }
        /* return */ result
    }
}

/** this only works for prime field curves (m = 1) */
private inline fun hashToFieldRFC9380ForPrimeField
            (crossinline em: ExpandMessageFn, p: BigInteger, L: Int, domain: ByteArray) : HashToFieldFn =
    { msg: Sequence<ByteArray>, count: Int ->
        val lenInBytes = count * L
        val uniformBytes = em(msg, domain, lenInBytes)
        /* return */ Array(count) {
            val tv = uniformBytes.readByteArray(L)
            BigInteger.fromByteArray(tv, Sign.POSITIVE).toModularBigInteger(p)
        }
    }

private inline fun hashToFieldRFC9380ForPrimeField
            (crossinline em: ExpandMessageFn, curve: ECCurve, domain: ByteArray): HashToFieldFn =
    hashToFieldRFC9380ForPrimeField(em, curve.modulus, curve.L, domain)

private inline fun sgn0ForPrimeFields(a: ModularBigInteger): Int = a.toBigInteger().mod(BigInteger.TWO).intValue()
/** RFC9380: appendix F.2.1.2. (sqrt_ratio_3mod4); only works for p mod 4 = 3 */
private inline fun ECCurve.sqrtRatio3mod4(u: ModularBigInteger, v: ModularBigInteger): Pair<Boolean, ModularBigInteger> {
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
private inline fun mapToCurveSimplifiedSWUWeierstrassABNonZero(curve: ECCurve)
        : MapToCurveFn
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
/* 18.*/val (isGx1Square, y1) = curve.sqrtRatio3mod4(tv2, tv6)
/* 19.*/  y = tv1 * u
/* 20.*/  y = y * y1
/* 21.*/  x = CMOV(x, tv3, isGx1Square)
/* 22.*/  y = CMOV(y, y1, isGx1Square)
/* 23.*/val e1 = sgn0ForPrimeFields(u) == sgn0ForPrimeFields(y)
/* 24.*/  y = CMOV(-y, y, e1)
/* 25.*/  x = x / tv4
        /* return */ ECPoint.fromXY(curve, x, y)
    }
}

/** RFC9380: encode_to_curve */
private inline fun encodeToCurveComposition
            (crossinline htf: HashToFieldFn, crossinline mtc: MapToCurveFn, crossinline ccf: ClearCofactorFn) =
RFC9380.HashToEllipticCurve { msg: Sequence<ByteArray> ->
    val u = htf(msg, 1)
    val Q = mtc(u[0])
    val P = ccf(Q)
    /*return*/ P
}

/** RFC9380: hash_to_curve */
private inline fun hashToCurveComposition
            (crossinline htf: HashToFieldFn, crossinline mtc: MapToCurveFn, crossinline ccf: ClearCofactorFn) =
RFC9380.HashToEllipticCurve { msg: Sequence<ByteArray> ->
    val u = htf(msg, 2)
    val Q0 = mtc(u[0])
    val Q1 = mtc(u[1])
    val R = Q0 + Q1
    val P = ccf(R)
    /*return*/ P
}

private inline fun <T> CMOV(a: T, b: T, c: Boolean) = if (c) b else a

object RFC9380 {
    @JvmInline
    value class HashToECScalar(private val fn: HashToFieldFn) {
        operator fun invoke(data: Sequence<ByteArray>) = fn(data, 1)[0]
        operator fun invoke(data: ByteArray) = fn(sequenceOf(data), 1)[0]
        operator fun invoke(data: Iterable<ByteArray>) = fn(data.asSequence(), 1)[0]
        operator fun invoke(data: Sequence<ByteArray>, count: Int) = fn(data, count)
        operator fun invoke(data: ByteArray, count: Int) = fn(sequenceOf(data), count)
        operator fun invoke(data: Iterable<ByteArray>, count: Int) = fn(data.asSequence(), count)
    }

    @JvmInline
    value class HashToEllipticCurve(private val fn: (Sequence<ByteArray>)->ECPoint) {
        operator fun invoke(data: Sequence<ByteArray>) = fn(data)
        operator fun invoke(data: ByteArray) = fn(sequenceOf(data))
        operator fun invoke(data: Iterable<ByteArray>) = fn(data.asSequence())
    }

    /** the hash_to_field construction as specified in RFC9380;
     *   Usage: `hash_to_field(params)(input)`
     *  @see ECCurve.hashToScalar
     *  @see expand_message_xmd */
    fun hash_to_field(expandMessage: ExpandMessageFn, p: BigInteger, L: Int, domain: ByteArray) =
        HashToECScalar(hashToFieldRFC9380ForPrimeField(expandMessage, p, L, domain))

    /** the hash_to_field construction as specified in RFC9380;
     *   Usage: `hash_to_field(params)(input)`
     *
     *  Note that this produces an element of the underlying field (mod [ECCurve.modulus]).<br/>
     *   It does **not** produce a random scalar multiplier (mod [ECCurve.order]).
     *
     *  @see ECCurve.hashToScalar */
    fun hash_to_field(expandMessage: ExpandMessageFn, curve: ECCurve, domain: ByteArray) = when (curve) {
        ECCurve.SECP_256_R_1, ECCurve.SECP_384_R_1, ECCurve.SECP_521_R_1 ->
            HashToECScalar(hashToFieldRFC9380ForPrimeField(expandMessage, curve, domain))
    }

    /** the expand_message_xmd function as specified in RFC9380;
     *   Usage: `expand_message_xmd(params)(input)` */
    fun expand_message_xmd(digest: Digest) =
        expandMessageXMD(digest)

    /** the map_to_curve_simple_swu function as specified in RFC9380 */
    fun map_to_curve_simple_swu(curve: ECCurve) = when (curve) {
        ECCurve.SECP_256_R_1, ECCurve.SECP_384_R_1, ECCurve.SECP_521_R_1 ->
            mapToCurveSimplifiedSWUWeierstrassABNonZero(curve)
    }

    /** The P256_XMD:SHA-256_SSWU_RO_ suite as defined in RFC9380;
     *   Usage: `suite(dst)(input)`
     *  @see ECCurve.hashToCurve */
    fun `P256_XMD∶SHA-256_SSWU_RO_`(domain: ByteArray) =
        hashToCurveComposition(
            hashToFieldRFC9380ForPrimeField(expandMessageXMD(Digest.SHA256), ECCurve.SECP_256_R_1, domain),
            mapToCurveSimplifiedSWUWeierstrassABNonZero(ECCurve.SECP_256_R_1),
            ::clearCofactorTrivial)

    /** The P256_XMD:SHA-256_SSWU_NU_ suite as defined in RFC9380;
     *   Usage: `suite(dst)(input)`
     *  @see ECCurve.hashToCurve */
    fun `P256_XMD∶SHA-256_SSWU_NU_`(domain: ByteArray) =
        encodeToCurveComposition(
            hashToFieldRFC9380ForPrimeField(expandMessageXMD(Digest.SHA256), ECCurve.SECP_256_R_1, domain),
            mapToCurveSimplifiedSWUWeierstrassABNonZero(ECCurve.SECP_256_R_1),
            ::clearCofactorTrivial)

    /** The P384_XMD:SHA-384_SSWU_RO_ suite as defined in RFC9380;
     *   Usage: `suite(dst)(input)`
     *  @see ECCurve.hashToCurve */
    fun `P384_XMD∶SHA-384_SSWU_RO_`(domain: ByteArray) =
        hashToCurveComposition(
            hashToFieldRFC9380ForPrimeField(expandMessageXMD(Digest.SHA384), ECCurve.SECP_384_R_1, domain),
            mapToCurveSimplifiedSWUWeierstrassABNonZero(ECCurve.SECP_384_R_1),
            ::clearCofactorTrivial)

    /** The P384_XMD:SHA-384_SSWU_NU_ suite as defined in RFC9380;
     *   Usage: `suite(dst)(input)`
     *  @see ECCurve.hashToCurve */
    fun `P384_XMD∶SHA-384_SSWU_NU_`(domain: ByteArray) =
        encodeToCurveComposition(
            hashToFieldRFC9380ForPrimeField(expandMessageXMD(Digest.SHA384), ECCurve.SECP_384_R_1, domain),
            mapToCurveSimplifiedSWUWeierstrassABNonZero(ECCurve.SECP_384_R_1),
            ::clearCofactorTrivial)

    /** The P521_XMD:SHA-512_SSWU_RO_ suite as defined in RFC9380;
     *   Usage: `suite(dst)(input)`
     *  @see ECCurve.hashToCurve */
    fun `P521_XMD∶SHA-512_SSWU_RO_`(domain: ByteArray) =
        hashToCurveComposition(
            hashToFieldRFC9380ForPrimeField(expandMessageXMD(Digest.SHA512), ECCurve.SECP_521_R_1, domain),
            mapToCurveSimplifiedSWUWeierstrassABNonZero(ECCurve.SECP_521_R_1),
            ::clearCofactorTrivial)

    /** The P521_XMD:SHA-512_SSWU_NU_ suite as defined in RFC9380;
     *   Usage: `suite(dst)(input)`
     *  @see ECCurve.hashToCurve */
    fun `P521_XMD∶SHA-512_SSWU_NU_`(domain: ByteArray) =
        encodeToCurveComposition(
            hashToFieldRFC9380ForPrimeField(expandMessageXMD(Digest.SHA512), ECCurve.SECP_521_R_1, domain),
            mapToCurveSimplifiedSWUWeierstrassABNonZero(ECCurve.SECP_521_R_1),
            ::clearCofactorTrivial)
}

/** Obtains a suitable secure hash-to-scalar function as defined in [RFC9380].
 * @param domain a suitable _domain separation tag_ (DST) for your use case;
 *                   this should be unique to this particular use case within your application!
 *                   see [RFC9380 3.1 Domain Separation Requirements](https://www.rfc-editor.org/rfc/rfc9380#name-domain-separation-requireme)
 *                      for guidance
 * @param L security parameter controlling the drift from uniform;
 *            defaults to `log2(modulus) * (3/2)`, which is the value used in RFC9380 suites
 * @return a function mapping arbitrary bytes to a scalar multiplier in [0, [ECCurve.order]) */
fun ECCurve.hashToScalar(domain: ByteArray, L: Int = this.L) = RFC9380.HashToECScalar(when (this) {
    ECCurve.SECP_256_R_1, ECCurve.SECP_384_R_1, ECCurve.SECP_521_R_1 ->
        hashToFieldRFC9380ForPrimeField(expandMessageXMD(this.nativeDigest), this.order, L, domain)
})

/** Obtains a suitable secure hash-to-curve suite as defined in [RFC9380].
 * @param domain a suitable _domain separation tag_ (DST) for your use case;
 *                   this should be unique to this particular use case within your application!
 *                   see [RFC9380 3.1 Domain Separation Requirements](https://www.rfc-editor.org/rfc/rfc9380#name-domain-separation-requireme)
 *                      for guidance */
inline fun ECCurve.hashToCurve(domain: ByteArray) = when (this) {
    ECCurve.SECP_256_R_1 -> RFC9380.`P256_XMD∶SHA-256_SSWU_RO_`(domain)
    ECCurve.SECP_384_R_1 -> RFC9380.`P384_XMD∶SHA-384_SSWU_RO_`(domain)
    ECCurve.SECP_521_R_1 -> RFC9380.`P521_XMD∶SHA-512_SSWU_RO_`(domain)
}
