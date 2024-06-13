//
//  Krypto.swift
//  SwiftCrypto
//

@objc public class Krypto: NSObject {

    fileprivate static func verifyECDSA_P256SHA256(_ pubkeyDER: Data, _ sigDER: Data, _ data: Data) throws -> Bool {
        let pubKey = try P256.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    fileprivate static func verifyECDSA_P384SHA384(_ pubkeyDER: Data, _ sigDER: Data, _ data: Data) throws -> Bool {
        let pubKey = try P384.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P384.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    fileprivate static func verifyECDSA_P521SHA512(_ pubkeyDER: Data, _ sigDER: Data, _ data: Data) throws -> Bool {
        let pubKey = try P521.Signing.PublicKey(derRepresentation: pubkeyDER)
        let sig = try P521.Signing.ECDSASignature(derRepresentation: sigDER)
        return pubKey.isValidSignature(sig, for: data)
    }

    @objc public class func verifyECDSA(_ alg: String, _ pubkeyDER: Data,
            _ sigDER: Data, _ data: Data)
            async throws -> Bool
    {
        switch digest {
            case "ECDSA_P256_SHA256": return verifyECDSA_P256SHA256(pubkeyDER, sigDER, data)
            case "ECDSA_P384_SHA384": return verifyECDSA_P384SHA384(pubkeyDER, sigDER, data)
            case "ECDSA_P521_SHA512": return verifyECDSA_P521SHA512(pubkeyDER, sigDER, data)
            default: throw RuntimeError("Unsupported algorithm \(alg)")
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
