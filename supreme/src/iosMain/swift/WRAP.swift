import CommonCrypto
import CryptoKit
import Foundation

@objc public class WRAP: NSObject {
  @objc public class func wrap(_ data: NSData, key: NSData) throws -> NSData {

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


    var padLength = size_t(kCCBlockSizeAES128 + data.length)

    var ciphertext = Data(count: padLength)

    let err = ciphertext.withUnsafeMutableBytes { ciph in
        CCSymmetricKeyWrap(
        CCWrappingAlgorithm(kCCWRAPAES),
        CCrfc3394_iv, CCrfc3394_ivLen,
        key.bytes, keySize,
        data.bytes, size_t(data.length),
        ciph.baseAddress!,  &padLength
      )
    }

    guard err == kCCSuccess else { throw NSError(domain: "AESwift", code: Int(err)) }

    ciphertext.removeSubrange(padLength..<size_t(kCCBlockSizeAES128 + data.length))
    return ciphertext as NSData
  }

    @objc public class func unwrap(_ data: NSData, key: NSData) throws -> NSData {

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

      var padLength = size_t(kCCBlockSizeAES128 + data.length)

      var ciphertext = Data(count: padLength)

      let err = ciphertext.withUnsafeMutableBytes { ciph in
          CCSymmetricKeyUnwrap(
          CCWrappingAlgorithm(kCCWRAPAES),
          CCrfc3394_iv, CCrfc3394_ivLen,
          key.bytes, keySize,
          data.bytes, size_t(data.length),
          ciph.baseAddress!,  &padLength
        )
      }

      guard err == kCCSuccess else { throw NSError(domain: "AESwift", code: Int(err)) }

      ciphertext.removeSubrange(padLength..<size_t(kCCBlockSizeAES128 + data.length))
      return ciphertext as NSData
    }
}
