import CommonCrypto
import CryptoKit
import Foundation

@objc public class ChaCha: NSObject {

  @objc public class func encrypt(_ plain: NSData, key: NSData, iv: NSData?, aad: NSData?) -> ChaChaAuthenticatedCiphertext? {
    let data = (key as Data)

      guard let nonce = if iv != nil { try! ChaChaPoly.Nonce(data: iv!) } else { ChaChaPoly.Nonce() }
                              else { return nil }

    let symmKey = SymmetricKey(data: data)

    let sealedBox = if aad != nil { try! ChaChaPoly.seal(plain, using: symmKey, nonce: nonce, authenticating: aad!) }
                             else { try! ChaChaPoly.seal(plain, using: symmKey, nonce: nonce) }

    return ChaChaAuthenticatedCiphertext(
      ciphertext: sealedBox.ciphertext,
      authTag: sealedBox.tag,
      iv: sealedBox.nonce.withUnsafeBytes { Data($0) })
  }

  @objc public class func decrypt(_ ciphertext: NSData, key: NSData, iv: NSData, tag: NSData, aad: NSData?) throws -> Data {
    let data = (key as Data)
    let nonce = try! ChaChaPoly.Nonce(data: iv)

    let symmKey = SymmetricKey(data: data)

    let sealedBox = try ChaChaPoly.SealedBox(
      nonce: nonce, ciphertext: ciphertext as Data, tag: tag as Data)

    let decrypted =
      if aad != nil {
        try ChaChaPoly.open(sealedBox, using: symmKey, authenticating: aad!)
      } else {

        try ChaChaPoly.open(sealedBox, using: symmKey)
      }
    return decrypted

  }
}

@objc public class ChaChaAuthenticatedCiphertext: NSObject {
  @objc public let ciphertext: Data

  @objc public let authTag: Data

  @objc public let iv: Data

  init(ciphertext: Data, authTag: Data, iv: Data) {
    self.ciphertext = ciphertext
    self.authTag = authTag
    self.iv = iv
  }

}
