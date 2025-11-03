package at.asitplus.signum.test


import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import de.infix.testBalloon.framework.TestDiscoverable
import de.infix.testBalloon.framework.TestElementName
import de.infix.testBalloon.framework.testSuite
import io.github.classgraph.ClassGraph
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.lang.reflect.ParameterizedType
import kotlin.reflect.full.companionObject
import kotlin.reflect.full.companionObjectInstance

@TestDiscoverable
fun enumConsistencyTest(@TestElementName name: String = "") = testSuite(name = name) {
    test(name) {
        ClassGraph()
            .enableClassInfo()
            .enableExternalClasses()
            .acceptPackages("at.asitplus.signum")
            .scan()
        .use { scanResult ->
            val companionsOfEnumerable =
                scanResult
                    .getClassesImplementing(Enumerable::class.java)
                    .loadClasses(Enumerable::class.java)
                    .asSequence()
                    .map(Class<Enumerable>::kotlin)
                    .mapNotNull { enumerableClass ->
                        val companionObject = enumerableClass.companionObject

                        if (enumerableClass.java.interfaces.contains(Enumerable::class.java)) {
                            /** If this class explicitly implements Enumerable, it must have a companion */
                            companionObject.shouldNotBeNull()
                        }

                        if (companionObject != null) {
                            /** If there is a companion, it needs to implement Enumeration<T> ... */
                            companionObject.java.genericInterfaces.asSequence()
                                .mapNotNull { it as? ParameterizedType }
                                .find { it.rawType == Enumeration::class.java }
                                .shouldNotBeNull() // It must implement Enumeration<*>
                                .actualTypeArguments[0] shouldBe enumerableClass.java // the type parameter must be T

                            /** ... and needs to be complete */
                            (enumerableClass.companionObjectInstance as Enumeration<*>).entries
                                .shouldContainAll(
                                    scanResult.getSubclasses(enumerableClass.java)
                                            .loadClasses(enumerableClass.java)
                                            .asSequence()
                                            .map(Class<*>::kotlin)
                                            .mapNotNull { it.objectInstance }
                                            .toSet())
                        }

                        /** map to the companion that we processed and validated */
                        companionObject
                    }
                    .toSet()

            val implementersOfEnumeration =
                scanResult
                    .getClassesImplementing(Enumeration::class.java)
                    .loadClasses(Enumeration::class.java)
                    .asSequence()
                    .map { it.kotlin.objectInstance.shouldNotBeNull() }
                    .toSet()

            implementersOfEnumeration shouldBe companionsOfEnumerable
        }
    }
}
