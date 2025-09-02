import de.infix.testBalloon.framework.Test
import de.infix.testBalloon.framework.TestSuite

context(test: Test)
operator fun String.invoke(nested: suspend () -> Unit) {
    test.testElementParent!!.test("${test.testElementName}.$this") { nested() }
}


@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
context(suite: TestSuite)
operator fun String.invoke(nested: suspend () -> Unit) {
    suite.test(this) { nested() }
}

context(suite: TestSuite)
infix operator fun String.minus(testBody: suspend (suite: TestSuite) -> Unit) {
    suite.test(this) {testBody(suite)}
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