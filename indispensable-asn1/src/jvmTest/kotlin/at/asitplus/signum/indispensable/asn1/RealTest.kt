package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.writeAsn1Real
import io.kotest.core.spec.style.FreeSpec
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

class RealTest :FreeSpec(
    {
        "Real" {

            val b= Buffer()
            b.writeAsn1Real(1398101.25)
            @OptIn(kotlin. ExperimentalStdlibApi::class)
            println( Asn1Primitive(BERTags.REAL,b.readByteArray()).toDerHexString())
          }

    }
)