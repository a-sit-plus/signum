package at.asitplus.signum.provider

import at.asitplus.awesn1.encoding.toUnsignedByteArray
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.supreme.azString
import at.asitplus.signum.supreme.os.SigningProviderI
import at.asitplus.signum.indispensable.sign.makeVerifier
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature
import at.asitplus.testballoon.matrix.matrixSuite
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlin.random.Random

val ParallelismTest by matrixSuite {
    "10k Loop" {
        getTestProvider().let { provider ->
            List(100) { i -> launch {
                val alias = "${Random.azString(64)}-$i"
                provider.createSigningKey(alias)
                List(100) { j -> launch {
                    val signer = provider.getSignerForKey(alias)
                    val sig = signer.sign(j.toUnsignedByteArray()).signature
                    val verifier = provider.getSignerForKey(alias).makeVerifier()
                    verifier.verify(j.toUnsignedByteArray(), sig)
                }}.joinAll()
                provider.deleteSigningKey(alias)
            }}.joinAll()
        }
    }
}

expect fun getTestProvider(): SigningProviderI<*, *, *>