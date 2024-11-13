import Foundation

import Foundation
import CryptoKit

@objc public class AESwift: NSObject {
  @objc public class func cryptoDemoCombinedData(plain: Data, key: Data, iv: Data, aad: Data) -> Data? {

    let nonce = try! AES.GCM.Nonce(data: iv)
    let symmKey = SymmetricKey(data: key)

    // Encrypt
    let sealedBox = try! AES.GCM.seal(
      plain, using: symmKey, nonce: nonce, authenticating: aad)

    return sealedBox.combined
  }
}
