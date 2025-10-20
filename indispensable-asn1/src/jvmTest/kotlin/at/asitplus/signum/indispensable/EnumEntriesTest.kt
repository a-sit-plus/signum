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
    "Asn1Enums" {
        val all = findImplementations<Enumerable>()
        var enum: Enumeration<*>? = null
        val discovered = mutableListOf<KClass<out Enumerable>>()
        all.forEach {
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
        all.filter { !it.kotlin.isAbstract } shouldContainAll discovered
    }
})