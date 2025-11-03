package at.asitplus.signum.test


import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import de.infix.testBalloon.framework.TestDiscoverable
import de.infix.testBalloon.framework.TestElementName
import de.infix.testBalloon.framework.testSuite
import io.github.classgraph.ClassGraph
import io.github.classgraph.ScanResult
import io.kotest.assertions.asClue
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type
import kotlin.reflect.full.companionObject

private val Type.rawType: Type get() = when (this) {
    is ParameterizedType -> this.rawType
    else -> this
}

private val GLOBAL_IGNORES = setOf(
    $$"at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm$Companion$AESDefinition"
)

/** do this manually because getClassesImplementing does not return sub-interfaces, and getSubclasses is not transitive */
private fun <T> ScanResult.loadAllTransitiveSubclassesAndSubinterfaces(superclass: Class<T>) =
    getClassesImplementing(superclass).loadClasses(superclass).asSequence() +
            this.allInterfaces.asSequence()
                .filter { it.implementsInterface(superclass) }
                .map { it.loadClass(superclass) }

@TestDiscoverable
fun enumConsistencyTest(@TestElementName name: String = "") = testSuite(name = name) { test("Enum consistency") {
    ClassGraph()
        .enableClassInfo()
        .enableExternalClasses()
        .acceptPackages("at.asitplus.signum")
        .scan()
        .use { scanResult ->
            val companionsOfEnumerable =
                scanResult
                    .loadAllTransitiveSubclassesAndSubinterfaces(Enumerable::class.java)
                    .map(Class<Enumerable>::kotlin)
                    .mapNotNull { enumerableClass ->
                        withClue(enumerableClass) {
                            val companionObject = enumerableClass.companionObject

                            if (enumerableClass.java.interfaces.contains(Enumerable::class.java)) {
                                /** If this class explicitly implements Enumerable, it must have a companion */
                                companionObject.shouldNotBeNull()
                            }

                            if (companionObject != null) {
                                "if there is a companion, it needs to implement Enumeration<T>".asClue {
                                    companionObject.java.genericInterfaces.asSequence()
                                        .mapNotNull { it as? ParameterizedType }
                                        .find { it.rawType == Enumeration::class.java }
                                        .let {
                                            "it must implement Enumeration<*>...".asClue { _ ->
                                                it.shouldNotBeNull()
                                            }
                                        }.let {
                                            "... and the type parameter must be T".asClue { _ ->
                                                it.actualTypeArguments[0].rawType shouldBe enumerableClass.java
                                            }
                                        }

                                }


                                "if there is a companion, its .entries need to be complete".asClue {
                                    (companionObject.objectInstance as Enumeration<*>).entries
                                        .shouldContainAll(
                                            scanResult.getSubclasses(enumerableClass.java)
                                                .loadClasses(enumerableClass.java)
                                                .asSequence()
                                                .map(Class<*>::kotlin)
                                                .mapNotNull { it.objectInstance }
                                                .toSet())
                                }
                            }

                            /** map to the companion that we processed and validated */
                            companionObject?.objectInstance
                        }
                    }
                    .toSet()

            val implementersOfEnumeration =
                "only (companion) objects should implement Enumeration".asClue {
                    scanResult
                        .getClassesImplementing(Enumeration::class.java)
                        .loadClasses(Enumeration::class.java)
                        .asSequence()
                        .filterNot { GLOBAL_IGNORES.any { i -> it.name.startsWith(i) } }
                        .map { withClue(it) { it.kotlin.objectInstance } }
                        .toSet()
                }

            "all Enumerations should have been discovered as companions of Enumerables".asClue {
                implementersOfEnumeration shouldContainExactly companionsOfEnumerable
            }
        }
}}
