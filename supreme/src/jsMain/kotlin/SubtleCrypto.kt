/*
 * shamelessly ripped from https://github.com/whyoleg/cryptography-kotlin/blob/186a42095596d697d1bddc7cc7085464ebe24591/cryptography-providers/webcrypto/src/jsMain/kotlin/internal/SubtleCrypto.js.kt#L49
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*
import kotlin.js.Promise

internal external interface SubtleCrypto {
    fun digest(algorithmName: String, data: ByteArray): Promise<ArrayBuffer>

}

//language=JavaScript
internal fun getSubtleCrypto(): SubtleCrypto {
    return js(
        code = """
    
        var isNodeJs = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
        if (isNodeJs) {
            return (eval('require')('node:crypto').webcrypto).subtle;
        } else {
            return (window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto).subtle;
        }
    
               """
    ).unsafeCast<SubtleCrypto>()
}