//
//  Krypto.swift
//  SwiftCrypto
//

import CryptoKit
import Foundation

@objc public class Krypto: NSObject {

    fileprivate static func verifyECDSA_P256(_ pubkeyDER: Data, _ sigDER: Data, _ data: any Digest) throws -> Bool {
        let pubKey = try P256.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    fileprivate static func verifyECDSA_P384(_ pubkeyDER: Data, _ sigDER: Data, _ data: any Digest) throws -> Bool {
        let pubKey = try P384.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P384.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    fileprivate static func verifyECDSA_P521(_ pubkeyDER: Data, _ sigDER: Data, _ data: any Digest) throws -> Bool {
        let pubKey = try P521.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P521.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    @objc public class func verifyECDSA(_ curve: String, _ digest: String, _ pubkeyDER: Data,
            _ sigDER: Data, _ data: Data) throws -> String
    {
        let hash: any Digest = switch digest {
            case "SHA256": SHA256.hash(data: data)
            case "SHA384": SHA384.hash(data: data)
            case "SHA512": SHA512.hash(data: data)
            default: throw RuntimeError("Unsupported digest \(digest)")
        }
        switch curve {
            case "P256": return try String(verifyECDSA_P256(pubkeyDER, sigDER, hash))
            case "P384": return try String(verifyECDSA_P384(pubkeyDER, sigDER, hash))
            case "P521": return try String(verifyECDSA_P521(pubkeyDER, sigDER, hash))
            default: throw RuntimeError("Unsupported curve \(curve)")
        }
    }
}

struct RuntimeError: LocalizedError {
    let description: String

    init(_ description: String) {
        self.description = description
    }

    var errorDescription: String? {
        description
    }
}
