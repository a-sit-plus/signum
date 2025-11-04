package at.asitplus.signum.supreme.symmetric.internal.ios

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ObjCObjectVar
import platform.Foundation.NSData
import platform.Foundation.NSError

object ChaCha {
    internal fun encrypt(data: Any, authenticatedData: Any, toNSData3: Any, toNSData4: NSData?): AuthenticatedCiphertext= TODO()

    @OptIn(ExperimentalForeignApi::class)
    @Throws(Exception::class)
    fun decrypt(
        ciphertext: NSData, key: NSData, iv: NSData, tag: NSData, aad: NSData?, error: CPointer<ObjCObjectVar<NSError?>>
    ): NSData =TODO()
}

object GCM {
    internal fun encrypt(data: Any, authenticatedData: Any, toNSData3: Any?, toNSData4: NSData?): AuthenticatedCiphertext= TODO()

    @OptIn(ExperimentalForeignApi::class)
    @Throws(Exception::class)
    fun decrypt(
        ciphertext: NSData, key: NSData, iv: NSData, tag: NSData, aad: NSData?, error: CPointer<ObjCObjectVar<NSError?>>
    ): NSData =TODO()
}

class AuthenticatedCiphertext{
    fun ciphertext(): NSData=TODO()
    fun authTag(): NSData=TODO()
    fun iv(): NSData=TODO()
}