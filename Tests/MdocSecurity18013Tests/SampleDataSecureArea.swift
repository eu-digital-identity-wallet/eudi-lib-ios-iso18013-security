/*
 Copyright (c) 2026 European Commission

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
@preconcurrency import CryptoKit
import Security
import MdocDataModel18013
@testable import MdocSecurity18013

/// Sample data secure area (test-only)
///
/// This SecureArea implementation uses iOS Cryptokit framework and allows
/// injecting a predetermined private key for testing purposes.
actor SampleDataSecureArea: SecureArea {

    let storage: any SecureKeyStorage
    private var x963Key: Data?

    init(storage: any SecureKeyStorage, x963Key: Data? = nil) {
        self.storage = storage
        self.x963Key = x963Key
    }

    /// Sets the x963 key representation for use in key creation.
    /// - Parameter key: The x963 representation of the private key.
    func setX963Key(_ key: Data?) {
        self.x963Key = key
    }
    nonisolated static func create(storage: any MdocDataModel18013.SecureKeyStorage) -> SampleDataSecureArea {
        SampleDataSecureArea(storage: storage)
    }
    static var supportedEcCurves: [CoseEcCurve] { [.P256, .P384, .P521] }
    func getStorage() async -> any MdocDataModel18013.SecureKeyStorage { storage }

    func createKeyBatch(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?) async throws -> [CoseKey] {
        let x963Priv: Data; let x963Pub: Data
        let curve = keyOptions?.curve ?? .P256
        switch curve {
        case .P256:
            let key = if let x963Key { try P256.Signing.PrivateKey(x963Representation: x963Key) } else { P256.Signing.PrivateKey() }
            x963Priv = key.x963Representation; x963Pub = key.publicKey.x963Representation
        case .P384:
            let key = if let x963Key { try P384.Signing.PrivateKey(x963Representation: x963Key) } else { P384.Signing.PrivateKey() }
            x963Priv = key.x963Representation; x963Pub = key.publicKey.x963Representation
        case .P521:
            let key = if let x963Key { try P521.Signing.PrivateKey(x963Representation: x963Key) } else { P521.Signing.PrivateKey() }
            x963Priv = key.x963Representation; x963Pub = key.publicKey.x963Representation
        default: throw SecureAreaError("Unsupported curve \(curve)")
        }
        let kbi = KeyBatchInfo(secureAreaName: Self.name, crv: curve, usedCounts: [0], credentialPolicy: .rotateUse)
        guard let kbiData = kbi.toData() else { throw SecureAreaError("Failed to encode KeyBatchInfo") }
        try await storage.writeKeyInfo(id: id, dict: [kSecValueData as String: kbiData, kSecAttrDescription as String: curve.jwkName.data(using: .utf8)!])
        try await storage.writeKeyDataBatch(id: id, startIndex: 0, dicts: [[kSecValueData as String: x963Priv]], keyOptions: keyOptions)
        return [CoseKey(crv: curve, x963Representation: x963Pub)]
    }

    func getPublicKey(id: String, index: Int, curve: CoseEcCurve) async throws -> CoseKey {
        let softwareSA = SoftwareSecureArea(storage: storage)
        return try await softwareSA.getPublicKey(id: id, index: index, curve: curve)
    }

    func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) async throws {
        try await storage.deleteKeyBatch(id: id, startIndex: startIndex, batchSize: batchSize)
    }

    func signature(id: String, index: Int, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?) async throws -> Data {
        let softwareSA = SoftwareSecureArea(storage: storage)
        return try await softwareSA.signature(id: id, index: index, algorithm: algorithm, dataToSign: dataToSign, unlockData: unlockData)
    }

    func keyAgreement(id: String, index: Int, publicKey: CoseKey, unlockData: Data?) async throws -> SharedSecret {
        let softwareSA = SoftwareSecureArea(storage: storage)
        return try await softwareSA.keyAgreement(id: id, index: index, publicKey: publicKey, unlockData: unlockData)
    }

    func getKeyBatchInfo(id: String) async throws -> KeyBatchInfo {
        let softwareSA = SoftwareSecureArea(storage: storage)
        return try await softwareSA.getKeyBatchInfo(id: id)
    }
    func deleteKeyInfo(id: String) async throws {
        try await storage.deleteKeyInfo(id: id)
    }
}
