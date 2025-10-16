import at.asitplus.signum.ecmath.CMOV
import io.kotest.core.spec.style.FunSpec
import kotlin.math.abs
import kotlin.random.Random
import kotlin.time.TimeSource



inline fun g() : Int = Random.nextInt(0, 2)
//fun fib(n: Int): Int = if (n <= 1) n else fib(n - 1) + fib(n - 2)
//inline fun g() = fib(3)

inline fun A() = 0
inline fun B() = g()

val NUM_TESTS = 10 // depending on machine, cpu speed might change -> using multiple runs for more stability
val TIMES_INNER = 1000000 // if set to low, startTime.elapsedNow().inWholeNanoseconds becomes too inprecise
val TIMES_OUTER = 1000 // if set to low, standard deviation messes up correlation computation

inline fun f(x: Int) : Int {
    val a = A()
    val b = B()
    return CMOV(a, b, x!=0) // CMOV is not constant time
}

inline fun <T> CMOV(a: T, b: T, c: Boolean) = if (c) b else a

inline fun CMOV_ALTERNATIVE(a: Int, b: Int, c: Int) = (1-c)*a+c*b

inline fun f_ALTERNATIVE(x: Int) : Int {
    val a = A()
    val b = B()
    // require(CMOV_ALTERNATIVE(a,b,x) == CMOV(a,b,xBool))  // TODO: comment in for testing, but note that this is not constant time because of CMOV
    return CMOV_ALTERNATIVE(a, b, x) // CMOV_ALTERNATIVE is constant time
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
        for (test in 0 until NUM_TESTS) {

            val xs = listOf(0,1)
            val results = mutableListOf<Pair<Int, Long>>() // (x, t)
            val variant = if(test%2 == 0) "CMOV" else "CMOV_ALTERNATIVE"
            println("test # $test with $variant:")

            repeat(TIMES_OUTER) {
                for (x in xs) {
                    var y : Int = 0
                    var deltaTime : Long

                    if (test%2 == 0)
                    {
                        val startTime = TimeSource.Monotonic.markNow()
                        repeat(TIMES_INNER)
                        {
                            y += f(x) // not constant time
                        }
                        deltaTime = startTime.elapsedNow().inWholeNanoseconds
                    }
                    else
                    {
                        val startTime = TimeSource.Monotonic.markNow()
                        repeat(TIMES_INNER)
                        {
                            y += f_ALTERNATIVE(x) // constant time
                        }
                        deltaTime = startTime.elapsedNow().inWholeNanoseconds
                    }

                    results += x to deltaTime
                }

            }

            val corr = correlation(results.map { it.first.toDouble() to it.second.toDouble() })
            var corrStr = correlationStrength(corr)
            println("  correlation: $corr ($corrStr)")
            println()
        }
    }
})