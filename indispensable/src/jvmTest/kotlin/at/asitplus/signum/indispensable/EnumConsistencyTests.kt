package at.asitplus.signum.indispensable

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.util.*
import kotlin.reflect.KClass
import kotlin.reflect.KProperty1
import kotlin.reflect.full.companionObject
import kotlin.reflect.full.memberProperties

inline fun <reified T : Any> FreeSpec.enumConsistencyTest() {
    T::class.simpleName!! {
        val listed = T::class.companionObject!!.let { companion ->
            @Suppress("UNCHECKED_CAST")
            (companion.memberProperties.find { it.name == "entries" }.shouldNotBeNull()
                    as KProperty1<Any, *>).get(companion.objectInstance!!)
        }.shouldBeInstanceOf<Iterable<T>>()

        val discovered = mutableSetOf<T>()
        val queue = Stack<KClass<out T>>().also { it.push(T::class) }
        while (!queue.empty()) {
            val cls = queue.pop()
            if (cls.java.isEnum) {
                discovered.addAll(cls.java.enumConstants!!)
                continue
            }
            val o = cls.objectInstance
            if (o != null) {
                discovered.add(o)
                continue
            }
            cls.sealedSubclasses.forEach(queue::push)
        }

        listed.toSet() shouldBe discovered.toSet()
    }
}

class EnumConsistencyTests : FreeSpec({
    //TODO the tests for these
    // enumConsistencyTest<MessageAuthenticationCode>()
    // enumConsistencyTest<DataIntegrityAlgorithm>()
})