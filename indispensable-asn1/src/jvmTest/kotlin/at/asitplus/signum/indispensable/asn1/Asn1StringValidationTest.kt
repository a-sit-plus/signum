package at.asitplus.signum.indispensable.asn1

import io.kotest.assertions.throwables.shouldThrow
import kotlinx.serialization.json.Json
import at.asitplus.testballoon.*
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.provided.at.asitplus.signum.indispensable.asn1.Asn1StringFixture


val Asn1StringValidationTest by testSuite{

    val json = Json
    val root = json.decodeFromString<Asn1StringFixture>(resourceText("asn1strings.json"))
    val tests = root.stringTests

    "NumericStringTest" {
        val data = tests.numeric
        data.valid.forEach { str ->
            Asn1String.Numeric(str).value shouldBe str
        }
        data.invalid.forEach { str ->
            shouldThrow<Asn1Exception> { Asn1String.Numeric(str) }
        }
    }

    "PrintableStringTest"  {
        val data = tests.printable
        data.valid.forEach { str ->
            Asn1String.Printable(str).value shouldBe str
        }
        data.invalid.forEach { str ->
            shouldThrow<Asn1Exception> { Asn1String.Printable(str) }
        }
    }

    "VisibleStringTest"  {
        val data = tests.visible
        data.valid.forEach { str ->
            Asn1String.Visible(str).value shouldBe str
        }
        data.invalid.forEach { str ->
            shouldThrow<Asn1Exception> { Asn1String.Visible(str) }
        }
    }

    "IA5StringTest"  {
        val data = tests.ia5
        data.valid.forEach { str ->
            Asn1String.IA5(str).value shouldBe str
        }
        data.invalid.forEach { str ->
            shouldThrow<Asn1Exception> { Asn1String.IA5(str) }
        }
    }

    "UTF8StringTest"  {
        val data = tests.utf8
        data.valid.forEach { str ->
            Asn1String.UTF8(str).value shouldBe str
        }
        data.invalid.forEach { str ->
            shouldThrow<Asn1Exception> { Asn1String.UTF8(str) }
        }
    }

    "TeletexStringTest"  {
        val data = tests.teletex
        data.valid.forEach { str ->
            Asn1String.Teletex(str).value shouldBe str
        }
    }

    "GraphicStringTest"  {
        val data = tests.graphic
        data.valid.forEach { str ->
            Asn1String.Graphic(str).value shouldBe str
        }
        data.invalid.forEach { str ->
            shouldThrow<Asn1Exception> { Asn1String.Graphic(str) }
        }
    }

    "BmpStringTest"  {
        val data = tests.bmp
        data.valid.forEach { str ->
            Asn1String.BMP(str).value shouldBe str
        }
    }

    "UniversalStringTest"  {
        val data = tests.universal
        data.valid.forEach { str ->
            Asn1String.Universal(str).value shouldBe str
        }
    }
}

private fun resourceText(path: String): String =
    Asn1StringValidationTest::class.java.classLoader?.getResourceAsStream(path)
        ?.reader(Charsets.UTF_8)
        ?.readText()
        ?: throw IllegalArgumentException("Resource not found: $path")