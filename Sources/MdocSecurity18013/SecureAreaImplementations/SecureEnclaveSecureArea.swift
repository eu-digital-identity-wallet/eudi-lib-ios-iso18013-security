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
    /// make key and return key tag
    public func createKey(crv: CoseEcCurve, keyInfo: KeyInfo?) throws -> Data {
        guard crv == Self.defaultEcCurve else { throw SecureAreaError("Unsupported curve \(crv)") }
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        // the data representation is opaque and used to recreate the key, therefore we dont need to save the key separetely
        return key.dataRepresentation
    }
    
    /// delete key
    public func deleteKey(keyTag: Data) throws {
        // nothing to do
    }
    /// compute signature
    public func signature(keyTag: Data, algorithm: SigningAlgorithm, dataToSign: Data, keyUnlockData: Data?) throws -> Data {
        guard algorithm == .ES256 else { throw SecureAreaError("Unsupported algorithm \(algorithm)") }
        let signingKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyTag)
        let signature = (try signingKey.signature(for: dataToSign)).rawRepresentation
        return signature
    }
    
    /// make shared secret with other public key
    public func keyAgreement(keyTag: Data, publicKey: Data, with curve: CoseEcCurve, keyUnlockData: Data?) throws -> SharedSecret {
        let puk256 = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        let prk256 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyTag)
        let sharedSecret = try prk256.sharedSecretFromKeyAgreement(with: puk256)
        return sharedSecret
    }
    
    /// returns information about the key with the given key
    public func getKeyInfo(keyTag: Data, keyUnlockData: Data?) throws -> KeyInfo {
       let prk256 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyTag)
        let keyInfo = KeyInfo(publicKey: prk256.publicKey.x963Representation, curve: .P256)
        return keyInfo
    }
}
