package at.asitplus.signum.test

import KOTEST_REPORT_TEMPDIR
import io.kotest.core.listeners.AfterProjectListener
import io.kotest.core.listeners.AfterSpecListener
import io.kotest.core.listeners.AfterTestListener
import io.kotest.core.spec.Spec
import io.kotest.core.spec.style.FreeSpec
import io.kotest.core.test.TestCase
import io.kotest.core.test.TestResult
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.writeString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import nl.adaptivity.xmlutil.core.XmlVersion
import nl.adaptivity.xmlutil.serialization.XML
import nl.adaptivity.xmlutil.serialization.XmlElement
import nl.adaptivity.xmlutil.serialization.XmlSerialName
import nl.adaptivity.xmlutil.serialization.XmlValue
import kotlin.math.round
import kotlin.time.Clock
import kotlin.time.DurationUnit
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid


@OptIn(ExperimentalUuidApi::class)
private val uniqueTestRun = Uuid.random().toString().substring(0, 10)
expect val target: String

/* ---------- platform hook ---------- */
private fun writeXmlFile(xml: String, filename: String) {

    val tempPath = Path(KOTEST_REPORT_TEMPDIR, "kotest-report", "test-results", target, uniqueTestRun)

    val path = Path(tempPath, filename)

    SystemFileSystem.createDirectories(tempPath)
    val sink = SystemFileSystem.sink(path, append = false).buffered()
    sink.writeString(xml)
    sink.close()

}

private fun Double.toThreeDecimals(): String {
    val multiplied = this * 1000
    val rounded = round(multiplied) / 1000
    return rounded.toString()
}


object DoubleSerializer : KSerializer<Double> {
    override val descriptor = PrimitiveSerialDescriptor("JunitXMLDouble", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Double) {
        encoder.encodeString(value.toThreeDecimals())
    }

    override fun deserialize(decoder: Decoder): Double {
        return decoder.decodeString().toDouble()
    }

}

@Serializable
@XmlSerialName("testsuite", "", "")
data class TestSuite(
    @XmlElement(false) val name: String,
    @XmlElement(false) val tests: Int,
    @XmlElement(false) val failures: Int,
    @XmlElement(false) val errors: Int,
    @XmlElement(false) val skipped: Int,
    @XmlElement(false) val timestamp: String,
    @XmlElement(false) @Serializable(with = DoubleSerializer::class) val time: Double,
    @XmlElement val cases: List<TestCaseXml>
)

@Serializable
@XmlSerialName("testcase", "", "")
data class TestCaseXml(
    @XmlElement(false) val classname: String,
    @XmlElement(false) val name: String,
    @XmlElement(false) @Serializable(with = DoubleSerializer::class) val time: Double,
    val failure: Failure? = null,
    val error: ErrorTag? = null,
    val skipped: Skipped? = null
)

@Serializable
@XmlSerialName("failure", "", "")
data class Failure(
    @XmlElement(false) val message: String,
    @XmlElement(false) val type: String,
    @XmlValue val stack: String
)

@Serializable
@XmlSerialName("error", "", "")
data class ErrorTag(
    @XmlElement(false) val message: String,
    @XmlElement(false) val type: String,
    @XmlValue val stack: String
)

@Serializable
@XmlSerialName("skipped", "", "")
class Skipped

/* ---------- Kotest listener that writes the file at engine stop ---------- */
class JUnitXmlReporter(
) : AfterTestListener, AfterProjectListener, AfterSpecListener {

    val bySpec = mutableMapOf<String, MutableList<Pair<TestCase, TestResult>>>()

    override suspend fun afterTest(testCase: TestCase, result: TestResult) {
        val spec = testCase.spec::class.simpleName ?: "UnknownSpec"
        bySpec.getOrPut(spec) { mutableListOf() } += testCase to result
    }


    override suspend fun afterSpec(spec: Spec) {
        val spec = spec::class.simpleName ?: "UnknownSpec"
        val suites = bySpec[spec].let { pairs ->
            var fails = 0;
            var errs = 0;
            var skips = 0
            val cases = pairs!!.map { (tc, res) ->
                val secs = res.duration.toDouble(DurationUnit.MILLISECONDS) / 1_000

                if (res.isFailure) fails++
                if (res.isError) errs++
                if (res.isIgnored) skips++
                val bld = mutableListOf<String>()
                var currentCase: TestCase? = tc
                while (currentCase != null) {
                    bld += currentCase.name.name
                    currentCase = currentCase.parent
                }
                val name = bld.reversed().joinToString(".")
                TestCaseXml(
                    classname = spec,
                    name = name,
                    time = secs,
                    failure = res.takeIf { it is TestResult.Failure }?.let {
                        (res as TestResult.Failure)
                        Failure(
                            res.errorOrNull?.message ?: "",
                            res.errorOrNull?.let { it::class.simpleName } ?: "",
                            res.errorOrNull?.stackTraceToString() ?: ""
                        )
                    },
                    error = res.takeIf { it is TestResult.Error }?.let {
                        (res as TestResult.Error)
                        ErrorTag(
                            res.errorOrNull?.message ?: "",
                            res.errorOrNull?.let { it::class.simpleName } ?: "",
                            res.errorOrNull?.stackTraceToString() ?: ""
                        )
                    },
                    skipped = res.takeIf { it is TestResult.Ignored }?.let { Skipped() }
                )
            }
            TestSuite(
                spec,
                cases.size,
                fails,
                errs,
                skips,
                Clock.System.now().toString(),
                cases.sumOf { it.time },
                cases
            )
        }

        val xml = XML {
            indentString = "  "
            xmlVersion = XmlVersion.XML10
        }
            .encodeToString(TestSuite.serializer(), (suites))

        @OptIn(ExperimentalUuidApi::class)
        writeXmlFile(
            xml,
            "TEST-$spec-${Uuid.random().toString().substring(0, 10)}.xml"
        )
    }

}
