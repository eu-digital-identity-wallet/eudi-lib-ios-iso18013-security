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
import MdocDataModel18013
/// Secure Enclave secure area
///
/// This SecureArea implementation is designed to utilize the Secure Enclave, a specialized hardware component found in iOS devices. The Secure Enclave acts as a hardware-based key manager, providing a secure environment for handling cryptographic keys and operations.
public actor SecureEnclaveSecureArea: SecureArea {

    var storage: any SecureKeyStorage
    init(storage: any SecureKeyStorage) {
        self.storage = storage
    }
    
    nonisolated public static func create(storage: any MdocDataModel18013.SecureKeyStorage) -> SecureEnclaveSecureArea {
        SecureEnclaveSecureArea(storage: storage)
    }
    public func getStorage() async -> any MdocDataModel18013.SecureKeyStorage { storage }

    public func createKeyBatch(id: String, keyOptions: KeyOptions?) async throws -> [CoseKey] {
        if let keyOptions, keyOptions.curve != Self.defaultEcCurve { throw SecureAreaError("Unsupported curve \(keyOptions.curve)") }
        let batchSize = keyOptions?.batchSize ?? 1
        var res: [CoseKey] = []; res.reserveCapacity(batchSize)
        var dicts = [[String: Data]](); dicts.reserveCapacity(batchSize)
        // create extra keys and save them as a batch with indexes from 1 to batch-size
        for _ in 0..<batchSize {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
            dicts.append([kSecValueData as String: key.dataRepresentation])
            res.append(CoseKey(crv: .P256, x963Representation: key.publicKey.x963Representation))
        }
        let kbi = KeyBatchInfo(secureAreaName: Self.name, crv: .P256, usedCounts: Array(repeating: 0, count: batchSize), credentialPolicy: keyOptions?.credentialPolicy ?? .rotateUse)
        try await storage.writeKeyInfo(id: id, dict: [kSecValueData as String: kbi.toData() ?? Data(), kSecAttrDescription as String: Self.defaultEcCurve.jwkName.data(using: .utf8)!])
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
        guard algorithm == .ES256 else { throw SecureAreaError("Unsupported algorithm \(algorithm)") }
        let keyDataDict = try await storage.readKeyData(id: id, index: index)
        guard let dataRepresentation = keyDataDict[kSecValueData as String] else { throw SecureAreaError("Key data not found") }
        let signingKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
        let signature = try signingKey.signature(for: dataToSign)
        logger.info("Creating signature for id: \(id), key index \(index)")
        return signature.rawRepresentation
    }

    /// make shared secret with other public key
    public func keyAgreement(id: String, index: Int, publicKey: CoseKey, unlockData: Data?) async throws -> SharedSecret {
        let puk256 = try P256.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation())
        let keyDataDict = try await storage.readKeyData(id: id, index: index)
        guard let dataRepresentation = keyDataDict[kSecValueData as String] else { throw SecureAreaError("Key data not found") }
        let prk256 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation)
        logger.info("Creating key agreement for id: \(id), key index \(index)")
        let sharedSecret = try prk256.sharedSecretFromKeyAgreement(with: puk256)
        return sharedSecret
    }

}
