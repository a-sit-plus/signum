package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborElement
import kotlinx.serialization.cbor.CborInteger
import kotlinx.serialization.cbor.CborLabel
import kotlinx.serialization.cbor.CborString

/**
 * [CoseHeaderWrapped] with an application-defined header model, raw buckets, `crit`, and the `x5chain` encoding of [CoseHeader]
 */
@OptIn(ExperimentalSerializationApi::class)
val CoseHeaderWrappedTest by matrixSuite {

    val kid = "kid".encodeToByteArray()
    val appHeader = AppHeader(algorithm = CoseAlgorithm.Signature.RS256, kid = kid, app = "x")

    "a custom header model is split into buckets by label" {
        val header = CoseHeaderWrapped(appHeader, unprotectedLabels = setOf(CborInteger(4)))
        val cose = CoseSign1(header = header, plainPayload = CONTENT) { FAKE_SIGNATURE }

        header.header shouldBe appHeader
        header.unprotectedLabels shouldBe setOf<CborElement>(CborInteger(4))
        cose.protectedHeader.keys shouldBe setOf<CborElement>(CborInteger(1), CborInteger(APP_LABEL))
        cose.unprotectedHeader.keys shouldBe setOf<CborElement>(CborInteger(4))
    }

    "a custom header model round-trips through CoseSign1" {
        val header = CoseHeaderWrapped(appHeader, unprotectedLabels = setOf(CborInteger(4)))
        val cose = CoseSign1(header = header, plainPayload = CONTENT) { FAKE_SIGNATURE }
        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose))

        parsed shouldBe cose
        parsed.wrappedHeader<AppHeader>() shouldBe header
        val typed = parsed.typed<ByteArray, AppHeader>()
        typed.header.app shouldBe "x"
        typed.signature shouldBe RsaSignature(FAKE_SIGNATURE)
    }

    "wrapper equality includes the placement of the parameters" {
        val allProtected = CoseHeaderWrapped(appHeader)
        val kidUnprotected = CoseHeaderWrapped(appHeader, unprotectedLabels = setOf(CborInteger(4)))

        allProtected.header shouldBe kidUnprotected.header
        allProtected shouldNotBe kidUnprotected
        allProtected shouldBe CoseHeaderWrapped(appHeader, AppHeader.serializer())
    }

    "the same message can be read with another header model; unknown parameters stay in the buckets" {
        val header = CoseHeaderWrapped(appHeader, unprotectedLabels = setOf(CborInteger(4)))
        val cose = CoseSign1(header = header, plainPayload = CONTENT) { FAKE_SIGNATURE }

        cose.wrappedHeader<CoseHeader>().header shouldBe RS256_HEADER.copy(kid = kid)
        cose.protectedHeader[APP_LABEL] shouldBe CborString("x")
    }

    "buckets can be inspected before choosing a header model" {
        val cose = CoseSign1(protectedHeader = RS256_HEADER.copy(type = "app+cose"), plainPayload = CONTENT) {
            FAKE_SIGNATURE
        }
        val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose))

        (parsed.protectedHeader[TYP_LABEL] as CborString).value shouldBe "app+cose"
        parsed.wrappedHeader<CoseHeader>().header.type shouldBe "app+cose"
    }

    "crit labels are read from the protected bucket" {
        // protected {1: -257, 2: [-65537], -65537: "x"}
        val protected = "A3" + "01390100" + "02813A00010000" + "3A00010000" + "6178"
        val wire = ("84" + "53" + protected + "A0" + "54" + CONTENT_HEX + "43" + FAKE_SIGNATURE.hex()).hexBytes()

        val header = CoseSign1(wire).wrappedHeader<AppHeader>()
        header.criticalLabels shouldBe listOf<CborElement>(CborInteger(APP_LABEL))
        header.header.app shouldBe "x"
    }

    "crit cannot be placed in the unprotected bucket when building" {
        shouldThrow<IllegalArgumentException> {
            CoseHeaderWrapped(RS256_HEADER.copy(criticalHeaders = "x"), unprotectedLabels = setOf(CborInteger(2)))
        }
    }

    "x5chain is a byte string for one certificate and an array for several" {
        val one = listOf(byteArrayOf(1, 2, 3))
        val two = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5))

        // {33: h'010203'}
        coseCompliantSerializer.encodeToByteArray(CoseHeader.serializer(), CoseHeader(certificateChain = one))
            .hex() shouldBe "A1" + "1821" + "43010203"
        // {33: [h'010203', h'0405']}
        coseCompliantSerializer.encodeToByteArray(CoseHeader.serializer(), CoseHeader(certificateChain = two))
            .hex() shouldBe "A1" + "1821" + "82" + "43010203" + "420405"
    }

    "x5chain with one or more certificates is decoded from bytes and from the buckets" {
        for (chain in listOf(listOf(byteArrayOf(1, 2, 3)), listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5)))) {
            val header = CoseHeader(certificateChain = chain)
            val bytes = coseCompliantSerializer.encodeToByteArray(CoseHeader.serializer(), header)
            coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), bytes) shouldBe header

            val cose = CoseSign1(protectedHeader = RS256_HEADER, unprotectedHeader = header, plainPayload = CONTENT) {
                FAKE_SIGNATURE
            }
            val parsed = CoseSign1(coseCompliantSerializer.encodeToByteArray(CoseSign1.serializer(), cose))
            parsed.wrappedHeader<CoseHeader>().header.certificateChain!!.map { it.hex() } shouldBe chain.map { it.hex() }
        }
    }

    "x5chain rejects values that are not byte strings" {
        // {33: 1}
        shouldThrow<SerializationException> {
            coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), "A1182101".hexBytes())
        }
    }

    "equal CoseHeaders with a certificate chain have equal hash codes" {
        val first = CoseHeader(certificateChain = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5)))
        val second = CoseHeader(certificateChain = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5)))

        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
    }

    "CoseTypedSerializerTemplate decodes a custom header model" {
        val typed = CoseTyped.sign1(
            header = CoseHeaderWrapped(appHeader),
            payload = CONTENT,
            payloadSerializer = ByteArraySerializer(),
        ) { FAKE_SIGNATURE }
        val template = CoseTypedSerializerTemplate(CoseSign1.serializer(), ByteArraySerializer(), AppHeader.serializer())

        coseCompliantSerializer.decodeFromByteArray(
            template,
            coseCompliantSerializer.encodeToByteArray(template, typed),
        ) shouldBe typed
    }
}

private const val APP_LABEL = -65537L
private const val TYP_LABEL = 16L

/** An application-defined header model with a private-use parameter. */
@Serializable
internal data class AppHeader(
    @CborLabel(1) @SerialName("alg") override val algorithm: CoseAlgorithm? = null,
    @CborLabel(4) @SerialName("kid") @ByteString override val kid: ByteArray? = null,
    @CborLabel(-65537) @SerialName("app") val app: String? = null,
) : CoseHeaderBase {
    @Transient override val contentType: String? = null
    @Transient override val iv: ByteArray? = null
    @Transient override val partialIv: ByteArray? = null
    @Transient override val certificateChain: List<ByteArray>? = null
    @Transient override val type: String? = null

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AppHeader) return false
        return algorithm == other.algorithm && kid.contentEquals(other.kid) && app == other.app
    }

    override fun hashCode(): Int {
        var result = algorithm?.hashCode() ?: 0
        result = 31 * result + (kid?.contentHashCode() ?: 0)
        result = 31 * result + (app?.hashCode() ?: 0)
        return result
    }
}