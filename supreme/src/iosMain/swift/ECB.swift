import CommonCrypto
import CryptoKit
import Foundation

@objc public class ECB: NSObject {
  @objc public class func crypt(_ operation: Int, data: NSData, key: NSData) throws -> NSData {

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
    let padLength = size_t(kCCBlockSizeAES128 + data.length)

    var ciphertext = Data(count: padLength)

    var bytesEncrypted = size_t(0)

    let err = ciphertext.withUnsafeMutableBytes { ciph in
      CCCrypt(
        CCOperation(operation),
        CCAlgorithm(kCCAlgorithmAES),
        CCOptions(kCCOptionECBMode),
        key.bytes, keySize,
        nil,
        data.bytes, size_t(data.length),
        ciph.baseAddress!, padLength,
        &bytesEncrypted
      )
    }

    guard err == kCCSuccess else { throw NSError(domain: "AESwift", code: Int(err)) }

    ciphertext.removeSubrange(bytesEncrypted..<padLength)
    return ciphertext as NSData
  }
}
