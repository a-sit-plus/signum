package io.kotest.property.at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.serialization.*
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.modules.SerializersModule
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(InternalSerializationApi::class)
val MixedPolyTests by testSuite(testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)) {

    val a = Choice.A
    val b = Choice.B

    val nestedA = Choice.Nested.A
    val nestedB = Choice.Nested.B("Foobar")
    val nestedC = Choice.Nested.Cnested(Choice.C(42, b))

    val withNestedProperties = Choice.WithNestedProperties(nestedC)

    val der = DER {
        serializersModule = SerializersModule {
            polymorphicByOid(Choice.Nested::class, serialName = "Nested") {
                subtype<Choice.Nested.A>(Choice.Nested.A)
                subtype<Choice.Nested.B>(Choice.Nested.B)
                subtype<Choice.Nested.Cnested>(Choice.Nested.Cnested)
            }
        }
    }

    withData(a, b, withNestedProperties) {
        val encoded = der.encodeToDer(it)
        println(encoded.toHexString())
        der.decodeFromDer<Choice>(encoded)
    }
    withData(nestedA, nestedB, nestedC) {
        val encoded = der.encodeToDer(it as Choice.Nested)
        println(encoded.toHexString())
        der.decodeFromDer<Choice.Nested>(encoded)
    }
}


@Serializable
sealed interface Choice {

    @Serializable
    object A : Choice

    @Serializable
    @Asn1Tag(123u)
    object B : Choice


    @Serializable
    @Asn1Tag(456u)
    data class C(val foo: Int, val b: B) : Choice

    @Serializable
    @Asn1Tag(789u)
    class WithNestedProperties(val nested: Nested) : Choice
    @Asn1Tag(10_11_12u)
    interface Nested : Choice, Identifiable {
        @Serializable
        object A : Nested, OidProvider<A> {
            @OptIn(ExperimentalUuidApi::class)
            override val oid: ObjectIdentifier
                get() = ObjectIdentifier(Uuid.parse("106b187f-4f00-4932-a9fe-575b6d5556ca"))
        }

        @Serializable
        class B(val bar: String) : Nested, Identifiable by Companion {
            companion object : OidProvider<B> {
                @OptIn(ExperimentalUuidApi::class)
                override val oid: ObjectIdentifier
                    get() = ObjectIdentifier(Uuid.parse("4acc3238-318a-4128-b9c4-4c03618eee64"))
            }
        }


        @Serializable
        class Cnested( val c: C) : Nested, Identifiable by Companion {
            companion object : OidProvider<Cnested> {
                @OptIn(ExperimentalUuidApi::class)
                override val oid: ObjectIdentifier
                    get() = ObjectIdentifier(Uuid.parse("f868d04b-2b77-4d34-bbaf-42558d044619"))
            }
        }
    }
}

