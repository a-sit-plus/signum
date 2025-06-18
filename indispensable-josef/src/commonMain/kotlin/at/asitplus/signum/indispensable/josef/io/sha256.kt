//public domain code copied and slightly adapted from https://github.com/asyncant/sha256-kt/blob/master/src/commonMain/kotlin/com/asyncant/crypto/Sha256.kt to get rid of okio dependency
/* *******************************************************************************************************************
 * SHA-256 hash algorithm implementation.
 *
 * Original C implementation by Brad Conte (brad@bradconte.com), https://github.com/B-Con/crypto-algorithms.
 * Ported to Kotlin and modified by asyncant.
 *
 * Like the original C implementation, this code is released into the public domain.
 *
 * ***************************************************************************************************************** */
package at.asitplus.signum.indispensable.josef.io

internal fun ByteArray.sha256(): ByteArray {
    val ctx = Sha256Ctx()
    sha256Update(ctx, this)
    return sha256Final(ctx)
}

private val k = longArrayOf(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
).map { it.toInt() }.toIntArray()

private class Sha256Ctx {
    var data: ByteArray = ByteArray(64)
    var state: IntArray = IntArray(8)
    var dataLength: Int = 0
    var bitLength: Long = 0

    init {
        state[0] = 0x6a09e667
        state[1] = 0xbb67ae85.toInt()
        state[2] = 0x3c6ef372
        state[3] = 0xa54ff53a.toInt()
        state[4] = 0x510e527f
        state[5] = 0x9b05688c.toInt()
        state[6] = 0x1f83d9ab
        state[7] = 0x5be0cd19
    }
}

private fun sha256Transform(ctx: Sha256Ctx, data: ByteArray, offset: Int) {
    var a: Int
    var b: Int
    var c: Int
    var d: Int
    var e: Int
    var f: Int
    var g: Int
    var h: Int
    var t1: Int
    var t2: Int
    val m = IntArray(64)

    for (i in 0 until 16) {
        val j = offset + i * 4
        m[i] = ((data[j].toInt() and 0xFF shl 24) or
                (data[j + 1].toInt() and 0xFF shl 16) or
                (data[j + 2].toInt() and 0xFF shl 8) or
                (data[j + 3].toInt() and 0xFF))
    }

    for (i in 16 until 64) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16]
    }
    a = ctx.state[0]
    b = ctx.state[1]
    c = ctx.state[2]
    d = ctx.state[3]
    e = ctx.state[4]
    f = ctx.state[5]
    g = ctx.state[6]
    h = ctx.state[7]

    for (i in 0 until 64) {
        t1 = h + ep1(e) + ch(e, f, g) + k[i] + m[i]
        t2 = ep0(a) + maj(a, b, c)
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    }

    ctx.state[0] += a
    ctx.state[1] += b
    ctx.state[2] += c
    ctx.state[3] += d
    ctx.state[4] += e
    ctx.state[5] += f
    ctx.state[6] += g
    ctx.state[7] += h
}

private fun sha256Update(ctx: Sha256Ctx, data: ByteArray) {
    val total = data.size - 64
    for (i in 0..total step 64) {
        sha256Transform(ctx, data, i)
        ctx.bitLength += 512
    }
    ctx.dataLength = data.size % 64
    val offset = (data.size / 64) * 64
    for (i in 0 until ctx.dataLength) ctx.data[i] = data[offset + i]
}

private fun sha256Final(ctx: Sha256Ctx): ByteArray {
    // Pad whatever data is left in the buffer.
    if (ctx.dataLength < 56) {
        ctx.data[ctx.dataLength] = 0x80.toByte()
        for (i in ctx.dataLength + 1 until 56) ctx.data[i] = 0
    } else {
        ctx.data[ctx.dataLength] = 0x80.toByte()
        for (i in ctx.dataLength + 1 until 64) ctx.data[i] = 0
        sha256Transform(ctx, ctx.data, 0)
        for (i in 0 until 56) ctx.data[i] = 0
    }

    // Append to the padding the total message's length in bits and transform.
    ctx.bitLength += ctx.dataLength * 8
    ctx.data[63] = (ctx.bitLength and 0xFF).toByte()
    ctx.data[62] = ((ctx.bitLength ushr 8) and 0xFF).toByte()
    ctx.data[61] = ((ctx.bitLength ushr 16) and 0xFF).toByte()
    ctx.data[60] = ((ctx.bitLength ushr 24) and 0xFF).toByte()
    ctx.data[59] = ((ctx.bitLength ushr 32) and 0xFF).toByte()
    ctx.data[58] = ((ctx.bitLength ushr 40) and 0xFF).toByte()
    ctx.data[57] = ((ctx.bitLength ushr 48) and 0xFF).toByte()
    ctx.data[56] = ((ctx.bitLength ushr 56) and 0xFF).toByte()
    sha256Transform(ctx, ctx.data, 0)

    // Since this implementation uses little endian byte ordering and SHA uses big endian,
    // reverse all the bytes when copying the final state to the output hash.
    val hash = ByteArray(32)

    for (i in 0 until 4) {
        hash[i] = ((ctx.state[0] ushr (24 - i * 8)) and 0xFF).toByte()
        hash[i + 4] = ((ctx.state[1] ushr (24 - i * 8)) and 0xFF).toByte()
        hash[i + 8] = ((ctx.state[2] ushr (24 - i * 8)) and 0xFF).toByte()
        hash[i + 12] = ((ctx.state[3] ushr (24 - i * 8)) and 0xFF).toByte()
        hash[i + 16] = ((ctx.state[4] ushr (24 - i * 8)) and 0xFF).toByte()
        hash[i + 20] = ((ctx.state[5] ushr (24 - i * 8)) and 0xFF).toByte()
        hash[i + 24] = ((ctx.state[6] ushr (24 - i * 8)) and 0xFF).toByte()
        hash[i + 28] = ((ctx.state[7] ushr (24 - i * 8)) and 0xFF).toByte()
    }
    return hash
}

private fun maj(x: Int, y: Int, z: Int) = (x and y) xor (x and z) xor (y and z)

private fun ep0(x: Int) = rotateRight(x, 2) xor rotateRight(x, 13) xor rotateRight(x, 22)

private fun ch(x: Int, y: Int, z: Int) = (x and y) xor (x.inv() and z)

private fun ep1(x: Int) = rotateRight(x, 6) xor rotateRight(x, 11) xor rotateRight(x, 25)

private fun sig0(x: Int) = rotateRight(x, 7) xor rotateRight(x, 18) xor (x ushr 3)

private fun sig1(x: Int) = rotateRight(x, 17) xor rotateRight(x, 19) xor (x ushr 10)

private fun rotateRight(a: Int, b: Int) = a ushr b or (a shl (32 - b))
