package at.asitplus.signum.indispensable

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.test.findImplementations
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.reflect.KClass
import kotlin.reflect.full.companionObject

class EnumEntriesTest : FreeSpec({

    val excludedClasses = setOf(
        "at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm\$",
        "at.asitplus.signum.indispensable.MessageAuthenticationCode\$Truncated",
        "at.asitplus.signum.indispensable.X509SignatureAlgorithm\$",
        "at.asitplus.signum.indispensable.asymmetric.RSAPadding\$",
    )

    "IndispensableEnums" {
        val all = findImplementations<Enumerable>()
        var enum: Enumeration<*>? = null
        val discovered = mutableListOf<KClass<out Enumerable>>()
        val filtered = all.filter { cls ->
            excludedClasses.none { exclude -> cls.name.startsWith(exclude) }
        }
        filtered.forEach {
            val cls = it.kotlin
            val companion = cls.companionObject
            companion.shouldNotBeNull()
            enum = companion.objectInstance.shouldBeInstanceOf<Enumeration<*>>()
            val entries = enum.entries
            entries.forEach {
                it::class shouldBe cls
                discovered.add(it::class)
            }
        }
        all.filter { !it.kotlin.isAbstract }.map { it.kotlin.qualifiedName } shouldContainAll discovered.map { it.qualifiedName }
    }
})