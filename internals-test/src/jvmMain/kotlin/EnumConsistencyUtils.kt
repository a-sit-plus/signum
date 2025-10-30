package at.asitplus.signum.test


import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import de.infix.testBalloon.framework.TestSuite
import io.github.classgraph.ClassGraph
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.lang.reflect.ParameterizedType
import kotlin.reflect.full.companionObject


inline fun <reified T : Any> findImplementations(packageRoot: String = ""): List<Class<out T>> =
    ClassGraph()
        .enableClassInfo()
        .enableExternalClasses()
        .acceptPackages(packageRoot) // or restrict: "com.example"
        .scan().use { scanResult ->
            return scanResult.getClassesImplementing(T::class.java.name)
                .filter { !it.isAbstract && !it.isInterface }
                .loadClasses(T::class.java)
        }

fun TestSuite.EnumConsistencyTestTemplate(testName: String, addedExcludes: Set<String> = setOf()) {
    val excludedClasses = if (addedExcludes.isNotEmpty()) (BASE_EXCLUDES + addedExcludes) else BASE_EXCLUDES


    test(testName) {
        val allEnumerables = findImplementations<Enumerable>(packageRoot = "at.asitplus.signum")
        val companionToEnumerable = allEnumerables.associateBy { it.kotlin.companionObject }
        findImplementations<Enumeration<*>>(packageRoot = "at.asitplus.signum").forEach { companion ->
            /** Every Enumeration<*> should be a companion */
            val surroundingClass = companionToEnumerable[companion.kotlin].shouldNotBeNull()

            /** Every Enumeration<*> should be parametrized with its own supertype */
            val enumerationImpl =
                companion.genericInterfaces.find { t -> t.javaClass == Enumeration::class.java } as ParameterizedType
            enumerationImpl.actualTypeArguments[0] shouldBe surroundingClass
        }
        allEnumerables.asSequence().filter { cls ->
            excludedClasses.none { exclude -> cls.name.startsWith(exclude) }
        }.map {
            val cls = it.kotlin
            val companion = cls.companionObject.shouldNotBeNull()
            companion.objectInstance.shouldBeInstanceOf<Enumeration<*>>().entries.forEach {
                it::class shouldBe cls
                // TODO: the entire logic is broken i think, reconsider
            }
        }
    }

}

val BASE_EXCLUDES = setOf(
    "at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm\$",
    "at.asitplus.signum.indispensable.MessageAuthenticationCode\$Truncated",
    "at.asitplus.signum.indispensable.X509SignatureAlgorithm\$",
    "at.asitplus.signum.indispensable.asymmetric.RSAPadding\$",
    "at.asitplus.signum.indispensable.cosef.CoseAlgorithm\$MAC\$",
    "at.asitplus.signum.indispensable.cosef.CoseAlgorithm\$Signature\$",
    "at.asitplus.signum.indispensable.cosef.CoseAlgorithm\$SymmetricEncryption\$",
    "at.asitplus.signum.indispensable.josef.JsonWebAlgorithm\$UNKNOWN"
)

