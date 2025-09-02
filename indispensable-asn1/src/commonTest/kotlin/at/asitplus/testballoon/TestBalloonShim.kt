package at.asitplus.testballoon

import de.infix.testBalloon.framework.TestSuite
import io.kotest.property.Gen
import io.kotest.property.PropTestConfig
import io.kotest.property.PropertyContext

context(suite: TestSuite)
operator fun String.invoke(nested: suspend () -> Unit) {
    suite.test(this) { nested() }
}

context(suite: TestSuite)
infix operator fun String.minus(suiteBody: TestSuite.() -> Unit) {
    suite.testSuite(this) { suiteBody() }
}


fun <Data> TestSuite.withData(vararg parameters: Data, action: suspend (Data) -> Unit) {
    for (data in parameters) {
        test("$data") {
            action(data)
        }
    }
}

fun <Data> TestSuite.withData(data: Iterable<Data>, action: suspend (Data) -> Unit) {
    for (d in data) {
        test("$d") { action(d) }
    }
}

fun <Data> TestSuite.withData(nameFn: (Data) -> String, data: Iterable<Data>, action: suspend (Data) -> Unit) {
    for (d in data) {
        test(nameFn(d)) { action(d) }
    }
}

fun <A> TestSuite.checkAll(
    iterations: Int,
    genA: Gen<A>,
    property: suspend PropertyContext.(A) -> Unit
) {
    test("$iterations times ${genA::class.simpleName}") {
        io.kotest.property.checkAll(iterations, genA, property)

    }
}

 fun <A> TestSuite.checkAll(
    genA: Gen<A>,
    property: suspend PropertyContext.(A) -> Unit
){
    test("${genA::class.simpleName}") {
        io.kotest.property.checkAll(genA, property)

    }
}