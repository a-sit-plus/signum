@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeTo
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.x500.OtherName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs

private val customOid = ObjectIdentifier("1.2.3.456")

private data class NameDocument(val oid: ObjectIdentifier, val text: String, val extra: String? = null)

private data class CustomName(val text: String) : OtherName {
    override val oid get() = customOid
    override val sourceRepresentation = SourceRepresentationStorage()
}

private class OpaqueName private constructor(source: NameDocument, diagnostic: UnsupportedCryptoException) :
    OtherName, ServiceLoader.UnknownShim(source, diagnostic) {
    override val oid = source.oid

    companion object {
        fun fromSource(source: NameDocument, diagnostic: UnsupportedCryptoException) = OpaqueName(source, diagnostic)
    }
}

private fun OtherName.toDocument() = encodeTo<NameDocument, OtherName> {
    val name = it as CustomName
    NameDocument(name.oid, name.text)
}

val OtherNameConversionTest by matrixSuite {
    "Custom OtherName conversions retain the source and encode fresh values" {
        val source = NameDocument(customOid, "  original  ", extra = "preserve this field")
        val decoded = decodeFrom<NameDocument, OtherName> { CustomName(it.text.trim()) }(source)
        decoded shouldBe CustomName("original")
        decoded.toDocument() shouldBeSameInstanceAs source
        CustomName("fresh").toDocument() shouldBe NameDocument(customOid, "fresh")
    }

    "A consumer module can own an opaque OtherName with its original diagnostic" {
        val source = NameDocument(ObjectIdentifier("1.2.3.457"), "opaque payload", extra = "metadata")
        val diagnostic = UnsupportedCryptoException("Unrecognized document OID")
        val decoded = decodeFrom<NameDocument, OtherName> { OpaqueName.fromSource(it, diagnostic) }(source)
        val opaque = decoded.shouldBeInstanceOf<OpaqueName>()
        opaque.oid shouldBe source.oid
        opaque.toDocument() shouldBeSameInstanceAs source
        opaque.lookupResult shouldBeSameInstanceAs diagnostic
        shouldThrow<UnsupportedCryptoException> {
            ServiceLoader.load<OtherNameAsn1Provider>().get(opaque, OtherNameAsn1Provider::encodeToAsn1)
        } shouldBeSameInstanceAs diagnostic
    }
}
