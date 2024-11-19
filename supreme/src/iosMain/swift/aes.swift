import Foundation
import CryptoKit

@objc public class AESwift: NSObject {
    @objc public class func gcm(plain: NSData, key: NSData, iv: NSData?, aad: NSData?) -> AuthenticatedCiphertext? {
      let data = (key as Data).withUnsafeBytes {
                      return Data($0)
                  }

      guard let nonce = if(iv != nil) {
          try! AES.GCM.Nonce(data: iv!)
      }else{          AES.GCM.Nonce()      }
      else {return nil}
      let symmKey = SymmetricKey(data: data)

    let sealedBox = if(aad != nil) {
        try! AES.GCM.seal(
        plain, using: symmKey, nonce: nonce, authenticating: aad!)
      }
      else {
        try!  AES.GCM.seal(
          plain, using: symmKey, nonce: nonce)
      }
            return AuthenticatedCiphertext(ciphertext: sealedBox.ciphertext, authTag: sealedBox.tag, iv: sealedBox.nonce.withUnsafeBytes { Data($0) })
      }

       @objc public class func gcmDecrypt(ciphertext: NSData, key: NSData, iv: NSData, tag: NSData, aad: NSData?) throws -> Data {
                  let data = (key as Data).withUnsafeBytes {
                                  return Data($0)
                              }
                      let nonce=try! AES.GCM.Nonce(data: iv)

                  let symmKey = SymmetricKey(data: data)

                  let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext as Data, tag: tag as Data)

                  let decrypted =
                  if(aad != nil)
                  {
                      try AES.GCM.open(sealedBox, using: symmKey, authenticating: aad!)
                  }
                  else {

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
