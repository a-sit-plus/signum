import at.asitplus.crypto.datatypes.JwsAlgorithm
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

class JwsAlgorithmAsn1Test : FreeSpec({
    "Encode and Decode should result result in the same SigAlg" - {
        withData(JwsAlgorithm.entries.filterNot { it == JwsAlgorithm.HS256 || it == JwsAlgorithm.HS384 || it == JwsAlgorithm.HS512 }) { algo ->
            JwsAlgorithm.decodeFromTlv( algo.encodeToTlv()) shouldBe algo
        }
    }
})