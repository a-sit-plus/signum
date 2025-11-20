package at.asitplus.signum.provider

import at.asitplus.signum.supreme.os.SigningProviderI
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch

val ParallelismTest by testSuite {
    val alias = "TestAlias"

    "10k Loop" {
        getTestProvider().let { provider ->
            val jobs = List(10000) {
                launch {
                    provider.deleteSigningKey(alias)
                    provider.getSignerForKey(alias)
                    provider.createSigningKey(alias)
                }
            }
            jobs.joinAll()
        }
    }
}

expect fun getTestProvider(): SigningProviderI<*, *, *>