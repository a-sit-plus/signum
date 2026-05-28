package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import java.util.Collections

private class JavaThreadRegisteredAttribute : BaseX509AttributeTypeAndValue {
    constructor(descriptor: JavaThreadRegistryDescriptor, value: String) :
            super(descriptor.oid, Asn1String.UTF8(value))

    internal constructor(src: X500AttributeTypeAndValue) : super(src)
}

private class JavaThreadRegistryDescriptor(
    override val oid: ObjectIdentifier,
    override val canonicalName: String,
    override val aliases: Set<String> = emptySet(),
) : AttributeTypeAndValue.Descriptor {
    override fun fromString(value: String) = JavaThreadRegisteredAttribute(this, value)

    override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = JavaThreadRegisteredAttribute(src)
}

val RdnRegistryJavaThreadConcurrencyTest by matrixSuite (
    matrixConfig { execution= ExecutionMode.Sequential }
) {
    "AttributeTypeAndValue registry tolerates Java thread reads while registering" {
        val failures = Collections.synchronizedList(mutableListOf<Throwable>())
        val descriptors = List(128) { index ->
            JavaThreadRegistryDescriptor(
                ObjectIdentifier("1.3.6.1.4.1.99999.1.2.$index"),
                "JAVATHREADRDN$index",
                setOf("JTRDN$index"),
            )
        }

        val threads = descriptors.map { descriptor ->
            Thread {
                try {
                    AttributeTypeAndValue.Registry.register(descriptor)
                    repeat(32) {
                        AttributeTypeAndValue.Registry.descriptorForName("CN") shouldBe
                                AttributeTypeAndValue.CommonName
                        AttributeTypeAndValue.Registry.descriptorFor(descriptor.oid) shouldBe descriptor
                        AttributeTypeAndValue.Registry.nameFor(descriptor.oid) shouldBe descriptor.canonicalName
                        AttributeTypeAndValue.fromString(descriptor.canonicalName, "value")!!::class shouldBe
                                JavaThreadRegisteredAttribute::class
                        AttributeTypeAndValue.fromString(descriptor.aliases.single(), "value")!!::class shouldBe
                                JavaThreadRegisteredAttribute::class
                    }
                } catch (cause: Throwable) {
                    failures += cause
                }
            }
        }

        threads.forEach { it.start() }
        threads.forEach { it.join() }

        failures.shouldBeEmpty()
        descriptors.forEach { descriptor ->
            AttributeTypeAndValue.Registry.descriptorFor(descriptor.oid) shouldBe descriptor
        }
    }
}
