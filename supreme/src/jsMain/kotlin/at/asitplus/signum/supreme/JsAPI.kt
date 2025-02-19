package at.asitplus.signum.supreme

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.promise
import kotlin.js.Promise

@OptIn(ExperimentalStdlibApi::class)
@JsExport
@JsName("someAPI")
fun someApi(foo: String): Promise<String> {
    return GlobalScope.promise {
        Digest.SHA256.digest(bytes = foo.encodeToByteArray()).toHexString()
    }
}