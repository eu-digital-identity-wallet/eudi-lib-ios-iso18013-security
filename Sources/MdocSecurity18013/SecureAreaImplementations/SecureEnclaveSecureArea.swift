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
    public init(storage: any SecureKeyStorage) {
        self.storage = storage
    }

    /// make key and return key tag
    public func createKey(id: String, keyOptions: KeyOptions) async throws {
        guard keyOptions.curve == Self.defaultEcCurve else { throw SecureAreaError("Unsupported curve \(keyOptions.curve)") }
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        try await storage.writeKeyInfo(id: id, dict: [kSecValueData as String: key.publicKey.x963Representation])
        try await storage.writeKeyData(id: id, dict: [kSecValueData as String: key.dataRepresentation])
    }

    /// delete key
    public func deleteKey(id: String) async throws {
        // nothing to do
    }
    /// compute signature
    public func signature(id: String, algorithm: SigningAlgorithm, dataToSign: Data, keyUnlockData: Data?) async throws -> Data {
        guard algorithm == .ES256 else { throw SecureAreaError("Unsupported algorithm \(algorithm)") }
        let keyDataDict = try await storage.readKeyData(id: id)
        guard let dataRepresentation = keyDataDict[kSecValueData as String] else { throw SecureAreaError("Key data not found") }
        let signingKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
        let signature = (try signingKey.signature(for: dataToSign)).rawRepresentation
        return signature
    }

    /// make shared secret with other public key
    public func keyAgreement(id: String, publicKey: CoseKey, keyUnlockData: Data?) async throws -> SharedSecret {
        let puk256 = try P256.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation())
        let keyDataDict = try await storage.readKeyData(id: id)
        guard let dataRepresentation = keyDataDict[kSecValueData as String] else { throw SecureAreaError("Key data not found") }
        let prk256 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation)
        let sharedSecret = try prk256.sharedSecretFromKeyAgreement(with: puk256)
        return sharedSecret
    }

    /// returns information about the key with the given key
    public func getKeyInfo(id: String) async throws -> KeyInfo {
        let keyInfoDict = try await storage.readKeyInfo(id: id)
        guard let x963Representation = keyInfoDict[kSecValueData as String] else { throw SecureAreaError("Key info not found") }
        let keyInfo = KeyInfo(publicKey: CoseKey(crv: .P256, x963Representation: x963Representation))
        return keyInfo
    }
}
