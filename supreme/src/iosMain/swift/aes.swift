import CommonCrypto
import CryptoKit
import Foundation

@objc public class AESwift: NSObject {

  @objc public class func cbc(_ operation: Int, data: NSData, key: NSData, iv: NSData?) throws -> NSData {

    let keySize =
      if key.length == 128 / 8 {
        kCCKeySizeAES128
      } else if key.length == 192 / 8 {
        kCCKeySizeAES192
      } else if key.length == 256 / 8 {
        kCCKeySizeAES256
      } else { 0 }

    if keySize == 0 {
      throw NSError(domain: "AESwift Key size", code: keySize)
    }

    if iv != nil { if iv?.length != 16 { throw NSError(domain: "AESwift IV Size", code: iv?.length ?? 0) } }

    let padLength = size_t(kCCBlockSizeAES128 + data.length)

    var ciphertext = Data(count: padLength)

    var bytesEncrypted = size_t(0)

    let err = ciphertext.withUnsafeMutableBytes { ciph in
      CCCrypt(
        CCOperation(operation),
        CCAlgorithm(kCCAlgorithmAES),
        CCOptions(kCCOptionPKCS7Padding),
        key.bytes, keySize,
        iv?.bytes,  // will be NULL if ivData is nil
        data.bytes, size_t(data.length),
        ciph.baseAddress!, padLength,
        &bytesEncrypted
      )
    }

    guard err == kCCSuccess else { throw NSError(domain: "AESwift", code: Int(err)) }

    ciphertext.removeSubrange(bytesEncrypted..<padLength)
    return ciphertext as NSData
  }

  @objc public class func gcm(plain: NSData, key: NSData, iv: NSData?, aad: NSData?) -> AuthenticatedCiphertext? {
    let data = (key as Data)

    guard let nonce = if iv != nil { try! AES.GCM.Nonce(data: iv!) } else { AES.GCM.Nonce() }
                              else { return nil }

    let symmKey = SymmetricKey(data: data)

    let sealedBox = if aad != nil { try! AES.GCM.seal(plain, using: symmKey, nonce: nonce, authenticating: aad!) }
                             else { try! AES.GCM.seal(plain, using: symmKey, nonce: nonce) }

    return AuthenticatedCiphertext(
      ciphertext: sealedBox.ciphertext,
      authTag: sealedBox.tag,
      iv: sealedBox.nonce.withUnsafeBytes { Data($0) })
  }

  @objc public class func gcmDecrypt(
    ciphertext: NSData, key: NSData, iv: NSData, tag: NSData, aad: NSData?
  ) throws -> Data {
    let data = (key as Data)
    let nonce = try! AES.GCM.Nonce(data: iv)

    let symmKey = SymmetricKey(data: data)

    let sealedBox = try AES.GCM.SealedBox(
      nonce: nonce, ciphertext: ciphertext as Data, tag: tag as Data)

    let decrypted =
      if aad != nil {
        try AES.GCM.open(sealedBox, using: symmKey, authenticating: aad!)
      } else {

        try AES.GCM.open(sealedBox, using: symmKey)
      }
    return decrypted

  }
}

@objc public class AuthenticatedCiphertext: NSObject {
  @objc public let ciphertext: Data

  @objc public let authTag: Data?

  @objc public let iv: Data

  init(ciphertext: Data, authTag: Data?, iv: Data) {
    self.ciphertext = ciphertext
    self.authTag = authTag
    self.iv = iv
  }

}
