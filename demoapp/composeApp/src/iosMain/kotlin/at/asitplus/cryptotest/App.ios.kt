package at.asitplus.cryptotest

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.os.SigningProvider
import io.ktor.util.encodeBase64
import platform.DeviceCheck.DCAppAttestService
import platform.posix.err
import kotlin.random.Random

actual val Provider: SigningProvider = PlatformSigningProvider

actual fun attestAndAssert() {
    DCAppAttestService.sharedService.generateKeyWithCompletionHandler { string, error ->
        if (error == null) {
            println("KID: $string")
            val challenge = Random.nextBytes(ByteArray(16))
            println("Challenge: ${challenge.encodeBase64()}")
            DCAppAttestService.sharedService.attestKey(
                string!!,
                Digest.SHA256.digest(challenge).toNSData()
            ) { data, error ->
                if (error == null) {
                    println("data: ${data!!.toByteArray().encodeBase64()}")
                    DCAppAttestService.sharedService.generateAssertion(
                        string,
                        Digest.SHA256.digest(challenge).toNSData()
                    ) { ok, error ->
                        if(error==null) println("Assertion: ${ok!!.toByteArray().encodeBase64()}")
                        DCAppAttestService.sharedService.generateAssertion(
                            string,
                            Digest.SHA256.digest(challenge).toNSData()
                        ) { ok, error ->
                            if(error==null) println("Assertion2: ${ok!!.toByteArray().encodeBase64()}")
                        }
                    }
                }

            }
        }
    }
}