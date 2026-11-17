@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.legacy.*
import at.asitplus.signum.indispensable.cosef.legacy.CoseHeader as FixtureHeader
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray

/** The old implementation is a test fixture only. Compare wire encodings and authenticated structures. */
val CoseSignedRegressionTest by matrixSuite {
    "Sign1 and Mac0 retain legacy wire and authentication bytes" {
        for (header in listOf(RS256_HEADER, HS256_HEADER)) for (aad in listOf(byteArrayOf(), EXTERNAL_AAD)) {
            val protectedBytes = header.toProtectedHeaderBytes()
            val legacy = CoseSigned.create(header, FixtureHeader(kid = byteArrayOf(1)), CONTENT, RsaSignature(FAKE_SIGNATURE), ByteArraySerializer())
            val bytes = legacy.serialize(ByteArraySerializer())
            val sign = CoseSign1.Raw<FixtureHeader>(bytes)
            val mac = CoseMac0.Raw<FixtureHeader>(bytes).typed<FixtureHeader, ByteArray>()
            sign.signatureInput(aad) shouldBe legacy.prepareCoseSignatureInput(aad)
            mac.macInput(aad) shouldBe COSE.mac0StructureInput(protectedBytes, aad, CONTENT)
            coseCompliantSerializer.encodeToByteArray(sign) shouldBe bytes
            coseCompliantSerializer.encodeToByteArray(mac) shouldBe bytes
            if (header.algorithm is CoseAlgorithm.Signature) {
                val typed = sign.typed<FixtureHeader, ByteArray>()
                typed.signatureInput(aad) shouldBe legacy.prepareCoseSignatureInput(aad)
                coseCompliantSerializer.encodeToByteArray(typed) shouldBe bytes
            }
        }
    }

    "Legacy typed payload bytes stay unchanged" {
        val payload = DataClass("bob")
        val legacy = CoseSigned.create(RS256_HEADER, null, payload, RsaSignature(FAKE_SIGNATURE), DataClass.serializer())
        val bytes = legacy.serialize(DataClass.serializer())
        val typed = CoseSign1<FixtureHeader, FixtureHeader, DataClass>(bytes)
        typed.payload shouldBe payload
        typed.raw.plainPayload shouldBe encodePayload(payload, DataClass.serializer())
        coseCompliantSerializer.encodeToByteArray(typed) shouldBe bytes
    }
}
