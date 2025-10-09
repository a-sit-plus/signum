
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.TestSuite
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.util.Stack
import kotlin.reflect.KClass
import kotlin.reflect.KProperty1
import kotlin.reflect.full.companionObject
import kotlin.reflect.full.memberProperties
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

inline fun<reified T: Any> TestSuite.enumConsistencyTest() {
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

        listed.sortedBy { it.toString() }.toSet() shouldBe discovered.sortedBy { it.toString() }.toSet()
    }
}

val EnumConsistencyTests by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 90.minutes)) {
    enumConsistencyTest<CoseAlgorithm>()
}