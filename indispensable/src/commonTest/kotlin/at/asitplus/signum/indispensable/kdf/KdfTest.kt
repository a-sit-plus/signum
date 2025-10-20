package at.asitplus.signum.indispensable.kdf

import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1ContentBytes

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.testScope
import de.infix.testBalloon.framework.testSuite
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.time.Duration.Companion.minutes

val KdfTest by testSuite {
   
    "Invoke Overrides"  {
        //withData is not working in all targets
        (List(10000) { it+1 }).forEach {
            PBKDF2.HMAC_SHA1.WithIterations(it) shouldBe PBKDF2.HMAC_SHA1(it).apply { pbkdf2 shouldBe PBKDF2.HMAC_SHA1 }
            PBKDF2.HMAC_SHA256.WithIterations(it) shouldBe PBKDF2.HMAC_SHA256(it).apply { pbkdf2 shouldBe PBKDF2.HMAC_SHA256 }
            PBKDF2.HMAC_SHA384.WithIterations(it) shouldBe PBKDF2.HMAC_SHA384(it).apply { pbkdf2 shouldBe PBKDF2.HMAC_SHA384 }
            PBKDF2.HMAC_SHA512.WithIterations(it) shouldBe PBKDF2.HMAC_SHA512(it).apply { pbkdf2 shouldBe PBKDF2.HMAC_SHA512 }

            PBKDF2.HMAC_SHA1.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA1(it*2)
            PBKDF2.HMAC_SHA256.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA256(it*2)
            PBKDF2.HMAC_SHA384.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA384(it*2)
            PBKDF2.HMAC_SHA512.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA512(it*2)

            PBKDF2.HMAC_SHA1.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA256(it)
            PBKDF2.HMAC_SHA1.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA384(it)
            PBKDF2.HMAC_SHA1.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA512(it)

            PBKDF2.HMAC_SHA256.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA1(it)
            PBKDF2.HMAC_SHA256.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA384(it)
            PBKDF2.HMAC_SHA256.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA512(it)

            PBKDF2.HMAC_SHA384.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA1(it)
            PBKDF2.HMAC_SHA384.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA256(it)
            PBKDF2.HMAC_SHA384.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA512(it)

            PBKDF2.HMAC_SHA512.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA1(it)
            PBKDF2.HMAC_SHA512.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA256(it)
            PBKDF2.HMAC_SHA512.WithIterations(it) shouldNotBe PBKDF2.HMAC_SHA384(it)


            HKDF.SHA1.WithInfo(it.encodeToAsn1ContentBytes()) shouldBe HKDF.SHA1(it.encodeToAsn1ContentBytes()).apply { hkdf shouldBe HKDF.SHA1}
            HKDF.SHA256.WithInfo(it.encodeToAsn1ContentBytes()) shouldBe HKDF.SHA256(it.encodeToAsn1ContentBytes()).apply { hkdf shouldBe HKDF.SHA256}
            HKDF.SHA384.WithInfo(it.encodeToAsn1ContentBytes()) shouldBe HKDF.SHA384(it.encodeToAsn1ContentBytes()).apply { hkdf shouldBe HKDF.SHA384}
            HKDF.SHA512.WithInfo(it.encodeToAsn1ContentBytes()) shouldBe HKDF.SHA512(it.encodeToAsn1ContentBytes()).apply { hkdf shouldBe HKDF.SHA512}

            HKDF.SHA1.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA1((-it).encodeToAsn1ContentBytes())
            HKDF.SHA256.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA256((-it).encodeToAsn1ContentBytes())
            HKDF.SHA384.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA384((-it).encodeToAsn1ContentBytes())
            HKDF.SHA512.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA512((-it).encodeToAsn1ContentBytes())

            HKDF.SHA1.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA256(it.encodeToAsn1ContentBytes())
            HKDF.SHA1.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA384(it.encodeToAsn1ContentBytes())
            HKDF.SHA1.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA512(it.encodeToAsn1ContentBytes())

            HKDF.SHA256.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA1(it.encodeToAsn1ContentBytes())
            HKDF.SHA256.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA384(it.encodeToAsn1ContentBytes())
            HKDF.SHA256.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA512(it.encodeToAsn1ContentBytes())

            HKDF.SHA384.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA1(it.encodeToAsn1ContentBytes())
            HKDF.SHA384.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA256(it.encodeToAsn1ContentBytes())
            HKDF.SHA384.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA512(it.encodeToAsn1ContentBytes())

            HKDF.SHA512.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA1(it.encodeToAsn1ContentBytes())
            HKDF.SHA512.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA256(it.encodeToAsn1ContentBytes())
            HKDF.SHA512.WithInfo(it.encodeToAsn1ContentBytes()) shouldNotBe HKDF.SHA384(it.encodeToAsn1ContentBytes())
        }
    }
}