package at.asitplus.signum.indispensable.asn1

import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

val KnownOIDTests by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {

    val dateDescription = KnownOIDs.date
    "Before Adding known OIDs" {
        KnownOIDs[dateDescription].shouldBeNull()
    }

    "After adding known descriptions" {
        KnownOIDs.describeAll()
        KnownOIDs[dateDescription].shouldNotBeNull()
    }

    "Own descriptions" {

        @OptIn(ExperimentalUuidApi::class)
        val expressionistOID = ObjectIdentifier(Uuid.random())

        KnownOIDs[expressionistOID].shouldBeNull()
        KnownOIDs[expressionistOID] = "Edvard Munch"
        KnownOIDs[expressionistOID] shouldBe "Edvard Munch"

    }
}