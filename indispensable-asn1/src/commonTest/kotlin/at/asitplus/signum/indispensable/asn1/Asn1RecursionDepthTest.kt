package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.ASN1_MAX_RECURSION_DEPTH
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

/**
 * Guards the band-aid in `Asn1Decoding.doParseExactly` that bounds the recursive descent parser by
 * [ASN1_MAX_RECURSION_DEPTH]. Deeply nested structures must be handled *cleanly* instead of blowing the
 * stack with a [StackOverflowError].
 *
 * "Cleanly" differs by tag, and the tests pin down both behaviours:
 *  - SEQUENCE / SET / EXPLICITLY TAGGED constructed structures throw an [Asn1StructuralException] once the
 *    limit is exceeded (the exception propagates straight up to the caller).
 *  - An (encapsulating) OCTET STRING instead falls back to a primitive octet string: the recursive decode
 *    of its content is best-effort, so hitting the limit there just means "don't recurse further".
 *
 * The limit itself is intentionally left untouched; the tests probe against the *actual* configured value
 * so they keep tracking it if it is ever changed.
 */
val Asn1RecursionDepthTest by matrixSuite {

    /** A leaf that the parser cannot recursively decode, so it stays primitive and survives round-tripping. */
    fun leaf(): Asn1Element = Asn1.OctetString(byteArrayOf(0x00))

    /** Builds [depth] nesting layers around a primitive leaf using [wrap] for every layer. */
    fun nest(depth: Int, wrap: (Asn1Element) -> Asn1Element): Asn1Element {
        var elem = leaf()
        repeat(depth) { elem = wrap(elem) }
        return elem
    }

    // ---- constructed structures that THROW past the limit -------------------------------------------------

    val throwing: List<Pair<String, (Asn1Element) -> Asn1Element>> = listOf(
        "SEQUENCE" to { child: Asn1Element -> Asn1.Sequence { +child } },
        "SET" to { child: Asn1Element -> Asn1.Set { +child } },
        "EXPLICITLY TAGGED" to { child: Asn1Element -> Asn1.ExplicitlyTagged(0xACu) { +child } },
    )

    /**
     * Probes upward to find the deepest nesting that still parses. Failures must be [Asn1Exception]s;
     * a [StackOverflowError] would NOT be caught here and would fail the surrounding test, which is
     * exactly what we want to guard against.
     */
    fun deepestParsable(wrap: (Asn1Element) -> Asn1Element): Int {
        var depth = 1
        while (true) {
            val encoded = nest(depth, wrap).derEncoded
            try {
                Asn1Element.parse(encoded)
            } catch (_: Asn1Exception) {
                return depth - 1
            }
            depth++
        }
    }

    throwing.forEach { (name, wrap) ->
        "deeply nested $name at the limit round-trips, one layer past it throws Asn1StructuralException" {
            val maxDepth = deepestParsable(wrap)
            // sanity: the limit must actually constrain something meaningful
            (maxDepth > 1) shouldBe true

            // the deepest still-parsable structure must survive a full round-trip
            val atLimit = nest(maxDepth, wrap)
            Asn1Element.parse(atLimit.derEncoded) shouldBe atLimit

            // exactly one layer deeper must be rejected cleanly (NOT a StackOverflowError)
            val overLimit = nest(maxDepth + 1, wrap).derEncoded
            shouldThrow<Asn1StructuralException> { Asn1Element.parse(overLimit) }
        }
    }

    "deeply nested mixture of SEQUENCE/SET/EXPLICITLY TAGGED at the limit round-trips, one layer past it throws Asn1StructuralException" {
        // cycle through every throwing container kind layer by layer
        var i = 0
        val mixed: (Asn1Element) -> Asn1Element = { child -> throwing[i++ % throwing.size].second(child) }
        // deepestParsable rebuilds from scratch each iteration, so reset the cursor per build
        fun build(depth: Int): Asn1Element {
            i = 0
            return nest(depth, mixed)
        }

        var maxDepth = 1
        while (true) {
            try {
                Asn1Element.parse(build(maxDepth).derEncoded); maxDepth++
            } catch (_: Asn1Exception) {
                maxDepth--; break
            }
        }
        (maxDepth > 1) shouldBe true

        val atLimit = build(maxDepth)
        Asn1Element.parse(atLimit.derEncoded) shouldBe atLimit
        shouldThrow<Asn1StructuralException> { Asn1Element.parse(build(maxDepth + 1).derEncoded) }
    }

    // ---- pathologically deep input via raw bytes (bypasses the recursive encoder) -------------------------

    /** DER length encoding (short form below 0x80, long form otherwise). */
    fun derLength(len: Int): ByteArray {
        if (len < 0x80) return byteArrayOf(len.toByte())
        val tmp = mutableListOf<Byte>()
        var v = len
        while (v > 0) {
            tmp.add(0, (v and 0xFF).toByte())
            v = v ushr 8
        }
        return byteArrayOf((0x80 or tmp.size).toByte()) + tmp.toByteArray()
    }

    /**
     * Builds raw DER bytes for [depth] nested containers (identified by [tag]) around a NULL leaf, *without*
     * going through the recursive encoder (whose length computation would itself hit the depth guard / overflow
     * the stack at extreme depths). This lets us hand the parser pathologically deep input directly.
     */
    fun rawNested(tag: Byte, depth: Int): ByteArray {
        var content = byteArrayOf(0x05, 0x00) // ASN.1 NULL as the innermost leaf
        repeat(depth) {
            content = byteArrayOf(tag) + derLength(content.size) + content
        }
        return content
    }

    "pathologically deep input throws Asn1StructuralException instead of overflowing the parser's stack" {
        val absurd = rawNested(0x30, ASN1_MAX_RECURSION_DEPTH * 64) // 0x30 = constructed SEQUENCE
        shouldThrow<Asn1StructuralException> { Asn1Element.parse(absurd) }
    }

    // ---- OCTET STRING degrades to a primitive past the limit (does NOT throw) -----------------------------

    "deeply nested OCTET STRING past the limit degrades to a primitive instead of overflowing the stack" {
        // shallow nesting is decoded recursively and round-trips faithfully
        val shallow = nest(4) { child -> Asn1.OctetStringEncapsulating { +child } }
        Asn1Element.parse(shallow.derEncoded) shouldBe shallow

        // raw bytes nested well past the recursion limit must still parse WITHOUT throwing: the inner decode bails
        // out and the offending octet string is kept as a primitive. A StackOverflowError here would fail the test.
        val deep = rawNested(0x04, ASN1_MAX_RECURSION_DEPTH * 64) // 0x04 = OCTET STRING
        Asn1Element.parse(deep) // returns normally; no exception, no stack overflow
    }

    // ---- encode / hashCode / toString / equals on pathologically deep TREES -------------------------------

    // Builds the nested SEQUENCE *object tree* directly (construction is lazy and does not recurse), so we can
    // hand the recursive operations a tree far deeper than they could ever recurse over.
    fun deepSequenceTree(depth: Int): Asn1Element {
        var elem: Asn1Element = leaf()
        repeat(depth) { elem = Asn1Sequence(listOf(elem)) }
        return elem
    }

    "recursive operations on a pathologically deep tree throw Asn1StructuralException instead of overflowing the stack" {
        val depth = ASN1_MAX_RECURSION_DEPTH * 4
        val tree = deepSequenceTree(depth)
        val sameTree = deepSequenceTree(depth) // distinct instance so equals cannot short-circuit on identity

        shouldThrow<Asn1StructuralException> { tree.derEncoded }      // encode
        shouldThrow<Asn1StructuralException> { tree.hashCode() }      // hashCode
        shouldThrow<Asn1StructuralException> { tree.toString() }      // toString
        shouldThrow<Asn1StructuralException> { tree.prettyPrint() }   // prettyPrint
        shouldThrow<Asn1StructuralException> { tree == sameTree }     // equals
    }

    "recursive operations on a tree within the limit still work" {
        // a tree comfortably below the limit must keep round-tripping through every recursive operation
        val tree = deepSequenceTree(ASN1_MAX_RECURSION_DEPTH / 4)
        val twin = deepSequenceTree(ASN1_MAX_RECURSION_DEPTH / 4)

        (tree == twin) shouldBe true
        (tree.hashCode() == twin.hashCode()) shouldBe true
        tree.toString() // does not throw
        Asn1Element.parse(tree.derEncoded) shouldBe tree
    }
}
