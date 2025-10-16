import at.asitplus.signum.ecmath.CMOV
import io.kotest.core.spec.style.FunSpec
import kotlin.math.abs
import kotlin.random.Random
import kotlin.time.TimeSource

inline fun g() = Random.nextInt(0, 2)

inline fun A() = g()
inline fun B() = g()-g()+g()

val TIMES_INNER = 100000
val TIMES_OUTER = 3000

suspend fun f(x: Int) : Int {
    var s = 0
    repeat(TIMES_INNER)
    {
        val a = A()
        val b = B()
        s += CMOV(a, b, x!=0) // CMOV is not constant time
    }
    return s
}

@Suppress("NOTHING_TO_INLINE")
inline fun CMOV_ALTERNATIVE(a: Int, b: Int, c: Int) = (1-c)*a+c*b

suspend fun f_ALTERNATIVE(x: Int) : Int {
    var s = 0
    repeat(TIMES_INNER)
    {
        val a = A()
        val b = B()
        // require(CMOV_ALTERNATIVE(a,b,x) == CMOV(a,b,xBool))  // TODO: comment in for testing, but note that this is not constant time because of CMOV
        s += CMOV_ALTERNATIVE(a, b, x) // CMOV_ALTERNATIVE is constant time
    }
    return s
}

fun correlation(data: List<Pair<Double, Double>>): Double {
    require(data.size > 1) {}
    val n = data.size
    val meanX = data.sumOf { it.first } / n
    val meanT = data.sumOf { it.second } / n
    val cov = data.sumOf { (x, t) -> (x - meanX) * (t - meanT) } / (n - 1)
    val sdX = kotlin.math.sqrt(data.sumOf { (x, _) -> (x - meanX) * (x - meanX) } / (n - 1))
    val sdT = kotlin.math.sqrt(data.sumOf { (_, t) -> (t - meanT) * (t - meanT) } / (n - 1))
    return cov / (sdX * sdT)
}

fun correlationStrength(r: Double): String {
    val a = abs(r)
    return when {
        a < 0.1 -> "none"
        a < 0.3 -> "weak"
        a < 0.5 -> "moderate"
        else     -> "strong"
    }
}

class TimingTest : FunSpec({
    test("measure time") {
        for (test in 0 until 10) {

            val xs = listOf(0,1)
            val results = mutableListOf<Pair<Int, Long>>() // (x, t)
            val variant = if(test%2 == 0) "CMOV" else "CMOV_ALTERNATIVE"
            println("test # $test with $variant:")
            for (x in xs) {
                var tSum = 0L
                var ySum = 0L

                repeat(TIMES_OUTER) {
                    var y : Int
                    var deltaTime : Long

                    if (test%2 == 0)
                    {
                        val startTime = TimeSource.Monotonic.markNow()
                        y = f(x) // not constant time
                        deltaTime = startTime.elapsedNow().inWholeNanoseconds
                    }
                    else
                    {
                        val startTime = TimeSource.Monotonic.markNow()
                        y = f_ALTERNATIVE(x) // constant time
                        deltaTime = startTime.elapsedNow().inWholeNanoseconds
                    }

                    results += x to deltaTime
                    tSum += deltaTime
                    ySum += y
                }

                println("  it took $tSum ns to compute f($x) = $ySum")
            }

            val corr = correlation(results.map { it.first.toDouble() to it.second.toDouble() })
            var corrStr = correlationStrength(corr)
            println("  correlation: $corr ($corrStr)")
            println()
        }
    }
})