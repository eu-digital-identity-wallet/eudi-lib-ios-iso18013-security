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
/// Sample data secure area
///
/// This SecureArea implementation uses iOS Cryptokit framework
public class SampleDataSecureArea: SecureArea, @unchecked Sendable {
    public var storage: any SecureKeyStorage
    public var x963Key: Data?
    
    required public init(storage: any SecureKeyStorage) {
        self.storage = storage
    }
    /// make key and return key tag
    public func createKey(id: String, keyOptions: KeyOptions?) throws -> CoseKey {
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
        try storage.writeKeyInfo(id: id, dict: [kSecValueData as String: x963Pub, kSecAttrDescription as String: curve.jwkName.data(using: .utf8)!])
        try storage.writeKeyData(id: id, dict: [kSecValueData as String: x963Priv], keyOptions: keyOptions)
        return CoseKey(crv: curve, x963Representation: x963Pub)
    }
    
    /// delete key
    public func deleteKey(id: String) throws {
        try storage.deleteKey(id: id)
    }
    /// compute signature
    public func signature(id: String, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?) throws -> (raw: Data, der: Data) {
        let softwareSA = SoftwareSecureArea(storage: storage)
        return try softwareSA.signature(id: id, algorithm: algorithm, dataToSign: dataToSign, unlockData: unlockData)
    }
    
    /// make shared secret with other public key
    public func keyAgreement(id: String, publicKey: CoseKey, unlockData: Data?) throws -> SharedSecret {
        let softwareSA = SoftwareSecureArea(storage: storage)
        return try softwareSA.keyAgreement(id: id, publicKey: publicKey, unlockData: unlockData)
    }
    
    /// returns information about the key with the given key
    public func getKeyInfo(id: String) throws -> KeyInfo {
        let softwareSA = SoftwareSecureArea(storage: storage)
        return try softwareSA.getKeyInfo(id: id)
    }

}
