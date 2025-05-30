/*
 Copyright (c) 2023 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import Foundation
import CryptoKit
import Security
import MdocDataModel18013
/// Software secure area
///
/// This SecureArea implementation uses iOS Cryptokit framework
public actor SoftwareSecureArea: SecureArea {

    var storage: any SecureKeyStorage
    init(storage: any SecureKeyStorage) {
        self.storage = storage
    }
    public func getStorage() async -> any MdocDataModel18013.SecureKeyStorage { storage }

    nonisolated public static func create(storage: any MdocDataModel18013.SecureKeyStorage) -> SoftwareSecureArea {
        SoftwareSecureArea(storage: storage)
    }
    
    public func createKeyMaterial(ecCurve: CoseEcCurve) throws -> (x963Priv: Data, x963Pub: Data) {
        switch ecCurve {
        case .P256: let key = P256.Signing.PrivateKey(compactRepresentable: false); return (key.x963Representation, key.publicKey.x963Representation)
        case .P384: let key = P384.Signing.PrivateKey(compactRepresentable: false); return (key.x963Representation, key.publicKey.x963Representation)
        case .P521: let key = P521.Signing.PrivateKey(compactRepresentable: false); return (key.x963Representation, key.publicKey.x963Representation)
        default: throw SecureAreaError("Unsupported curve \(ecCurve)")
        }
    }
    
    public func createKeyBatch(id: String, keyOptions: KeyOptions?) async throws -> [CoseKey] {
        let ecCurve = keyOptions?.curve ?? .P256
        let batchSize = keyOptions?.batchSize ?? 1
        var res: [CoseKey] = []; res.reserveCapacity(batchSize)
        var dicts = [[String: Data]](); dicts.reserveCapacity(batchSize)
        for _ in 0..<batchSize {
            let (x963Priv, x963Pub) = try createKeyMaterial(ecCurve: ecCurve)
            dicts.append([kSecValueData as String: x963Priv])
            res.append(CoseKey(crv: ecCurve, x963Representation: x963Pub))
        }
        let kbi = KeyBatchInfo(secureAreaName: Self.name, crv: ecCurve, usedCounts: Array(repeating: 0, count: batchSize), credentialPolicy: keyOptions?.credentialPolicy ?? .rotateUse)
        try await storage.writeKeyInfo(id: id, dict: [kSecValueData as String: kbi.toData() ?? Data(), kSecAttrDescription as String: ecCurve.jwkName.data(using: .utf8)!])
        try await storage.writeKeyDataBatch(id: id, startIndex: 0, dicts: dicts, keyOptions: keyOptions)
        return res
    }
    
    /// delete key
    public func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) async throws {
        try await storage.deleteKeyBatch(id: id, startIndex: startIndex, batchSize: batchSize)
    }
    public func deleteKeyInfo(id: String) async throws {
        try await storage.deleteKeyInfo(id: id)
    }
    /// compute signature
    public func signature(id: String, index: Int, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?) async throws -> Data {
        let x963Priv = try await getKeyData(id: id, index: index)
        switch algorithm {
        case .ES256:
            let signingKey = try P256.Signing.PrivateKey(x963Representation: x963Priv)
            logger.info("Creating signature with ES256 for id: \(id), key index \(index)")
            let signature = try signingKey.signature(for: dataToSign)
            return signature.rawRepresentation
        case .ES384:
            let signingKey = try P384.Signing.PrivateKey(x963Representation: x963Priv)
            logger.info("Creating signature with ES384 for id: \(id), key index \(index)")
            let signature = try signingKey.signature(for: dataToSign)
            return signature.rawRepresentation
        case .ES512:
            let signingKey = try P521.Signing.PrivateKey(x963Representation: x963Priv)
            logger.info("Creating signature with ES512 for id: \(id), key index \(index)")
            let signature = try signingKey.signature(for: dataToSign)
            return signature.rawRepresentation
        default: throw SecureAreaError("Unsupported algorithm \(algorithm)")
        }
    }

    /// make shared secret with other public key
    public func keyAgreement(id: String, index: Int, publicKey: CoseKey, unlockData: Data?) async throws -> SharedSecret {
        let sharedSecret: SharedSecret
        let (_, curve) = try await getInfoAndCurve(id: id)
        let x963Priv = try await getKeyData(id: id, index: index)
        switch curve {
        case .P256:
            let puk256 = try P256.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation())
            let prk256 = try P256.KeyAgreement.PrivateKey(x963Representation: x963Priv)
            logger.info("Creating P256 key agreement for id: \(id), key index \(index)")
            sharedSecret = try prk256.sharedSecretFromKeyAgreement(with: puk256)
        case .P384:
            let puk384 = try P384.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation())
            let prk384 = try P384.KeyAgreement.PrivateKey(x963Representation: x963Priv)
            logger.info("Creating P384 key agreement for id: \(id), key index \(index)")
            sharedSecret = try prk384.sharedSecretFromKeyAgreement(with: puk384)
        case .P521:
            let puk521 = try P521.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation())
            let prk521 = try P521.KeyAgreement.PrivateKey(x963Representation: x963Priv)
            logger.info("Creating P521 key agreement for id: \(id), key index \(index)")
            sharedSecret = try prk521.sharedSecretFromKeyAgreement(with: puk521)
        default: throw SecureAreaError("Unsupported curve \(publicKey.crv)")
        }
        return sharedSecret
    }

    func getInfoAndCurve(id: String) async throws -> ([String:Data], CoseEcCurve) {
        let keyInfoDict = try await storage.readKeyInfo(id: id)
        guard let jwkNameData = keyInfoDict[kSecAttrDescription as String], let jwkName = String(data: jwkNameData, encoding: .utf8) else { throw SecureAreaError("Key info description not found") }
        let curve = try CoseEcCurve.fromJwkName(jwkName)
        return (keyInfoDict, curve)
    }

    func getKeyData(id: String, index: Int) async throws -> Data {
        let keyDataDict = try await storage.readKeyData(id: id, index: index)
        guard let x963Representation = keyDataDict[kSecValueData as String] else { throw SecureAreaError("Key data not found") }
        return x963Representation
    }
}
