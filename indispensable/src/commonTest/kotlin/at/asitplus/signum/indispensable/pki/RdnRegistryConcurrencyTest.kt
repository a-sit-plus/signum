package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch

private class ConcurrentRegisteredAttribute : BaseX509AttributeTypeAndValue {
    constructor(descriptor: ConcurrentRegistryDescriptor, value: String) :
            super(descriptor.oid, Asn1String.UTF8(value))

    internal constructor(src: X500AttributeTypeAndValue) : super(src)
}

private class ConcurrentRegistryDescriptor(
    override val oid: ObjectIdentifier,
    override val canonicalName: String,
    override val aliases: Set<String> = emptySet(),
) : AttributeTypeAndValue.Descriptor {
    override fun fromString(value: String) = ConcurrentRegisteredAttribute(this, value)

    override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = ConcurrentRegisteredAttribute(src)
}

val RdnRegistryConcurrencyTest by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential),
) {
    "AttributeTypeAndValue registry tolerates coroutine reads while registering" {
        val descriptors = List(128) { index ->
            ConcurrentRegistryDescriptor(
                ObjectIdentifier("1.3.6.1.4.1.99999.1.1.$index"),
                "COROUTINERDN$index",
                setOf("CRDN$index"),
            )
        }

        val jobs = descriptors.map { descriptor ->
            launch {
                AttributeTypeAndValue.Registry.register(descriptor)
                repeat(32) {
                    AttributeTypeAndValue.Registry.descriptorForName("CN") shouldBe
                            AttributeTypeAndValue.CommonName
                    AttributeTypeAndValue.Registry.descriptorFor(descriptor.oid) shouldBe descriptor
                    AttributeTypeAndValue.Registry.nameFor(descriptor.oid) shouldBe descriptor.canonicalName
                    AttributeTypeAndValue.fromString(descriptor.canonicalName, "value")!!::class shouldBe
                            ConcurrentRegisteredAttribute::class
                    AttributeTypeAndValue.fromString(descriptor.aliases.single(), "value")!!::class shouldBe
                            ConcurrentRegisteredAttribute::class
                }
            }
        }
        jobs.joinAll()

        descriptors.forEach { descriptor ->
            AttributeTypeAndValue.Registry.descriptorFor(descriptor.oid) shouldBe descriptor
        }
    }
}
