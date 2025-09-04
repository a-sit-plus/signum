package at.asitplus.testballoon

import de.infix.testBalloon.framework.TestCoroutineScope
import de.infix.testBalloon.framework.TestSuite
import io.kotest.property.Arb
import io.kotest.property.Constraints
import io.kotest.property.PropTestConfig
import io.kotest.property.PropertyContext
import io.kotest.property.PropertyTesting
import io.kotest.property.RandomSource

context(suite: TestSuite)
operator fun String.invoke(nested: suspend TestCoroutineScope.() -> Unit) {
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

fun <Data> TestSuite.withDataSuites(
    nameFn: (Data) -> String,
    data: Iterable<Data>,
    action: TestSuite.(Data) -> Unit
) {
    for (d in data) {
        testSuite(nameFn(d)) { action(d) }
    }
}

fun <Value> TestSuite.checkAllTests(
    iterations: Int,
    genA: Arb<Value>,
    content: suspend context(PropertyContext) TestCoroutineScope.(Value) -> Unit
) {
    checkAllSeries(iterations, genA) { value, context ->
        test("$value") {
            with(context) {
                content(value)
            }
        }
    }
}

fun <Value> TestSuite.checkAllSuites(
    iterations: Int,
    genA: Arb<Value>,
    content: context(PropertyContext) TestSuite.(Value) -> Unit
) {
    checkAllSeries(iterations, genA) { value, context ->
        testSuite("$value") {
            with(context) {
                content(value)
            }
        }
    }
}

fun <A> TestSuite.checkAllSuites(
    genA: Arb<A>,
    content: context(PropertyContext) TestSuite.(A) -> Unit
) = checkAllSuites(PropertyTesting.defaultIterationCount, genA, content)

private inline fun <Value> checkAllSeries(iterations: Int, genA: Arb<Value>, series: (Value, PropertyContext) -> Unit) {
    val constraints = Constraints.iterations(iterations)

    @Suppress("OPT_IN_USAGE")
    val config = PropTestConfig(constraints = constraints)
    val context = PropertyContext(config)
    genA.generate(RandomSource.default(), config.edgeConfig)
        .takeWhile { constraints.evaluate(context) }
        .forEach { sample ->
            context.markEvaluation()
            series(sample.value, context)
            context.markSuccess()
        }
}
