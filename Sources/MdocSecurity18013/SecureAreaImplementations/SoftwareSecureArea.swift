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
/// Software secure area
///
/// This SecureArea implementation uses iOS Cryptokit framework
public actor SoftwareSecureArea: SecureArea {
    /// make key and return key tag
    public func createKey(crv: CoseEcCurve, keyInfo: KeyInfo?) throws -> Data {
        switch crv {
        case .P256: let key = P256.KeyAgreement.PrivateKey(); return key.x963Representation
        case .P384: let key = P384.KeyAgreement.PrivateKey(); return key.x963Representation
        case .P521: let key = P521.KeyAgreement.PrivateKey(); return key.x963Representation
        default: throw SecureAreaError("Unsupported curve \(crv)")
        }
    }
    
    /// delete key
    public func deleteKey(keyTag: Data) throws {
        // nothing to do
    }
    /// compute signature
    public func signature(keyTag: Data, algorithm: SigningAlgorithm, dataToSign: Data, keyUnlockData: Data?) throws -> Data {
        let signature: Data
        switch algorithm {
        case .ES256:
            let signingKey = try P256.Signing.PrivateKey(x963Representation: keyTag)
            signature = (try signingKey.signature(for: dataToSign)).rawRepresentation
        case .ES384:
            let signingKey = try P384.Signing.PrivateKey(x963Representation: keyTag)
            signature = (try signingKey.signature(for: dataToSign)).rawRepresentation
        case .ES512:
            let signingKey = try P521.Signing.PrivateKey(x963Representation: keyTag)
            signature = (try signingKey.signature(for: dataToSign)).rawRepresentation
        default: throw SecureAreaError("Unsupported algorithm \(algorithm)")
        }
        return signature
    }
    
    /// make shared secret with other public key
    public func keyAgreement(keyTag: Data, publicKey: Data, curve: CoseEcCurve, keyUnlockData: Data?) throws -> SharedSecret {
        let sharedSecret: SharedSecret
        switch curve {
        case .P256:
            let puk256 = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
            let prk256 = try P256.KeyAgreement.PrivateKey(x963Representation: keyTag)
            sharedSecret = try prk256.sharedSecretFromKeyAgreement(with: puk256)
        case .P384:
            let puk384 = try P384.KeyAgreement.PublicKey(x963Representation: publicKey)
            let prk384 = try P384.KeyAgreement.PrivateKey(x963Representation: keyTag)
            sharedSecret = try prk384.sharedSecretFromKeyAgreement(with: puk384)
        case .P521:
            let puk521 = try P521.KeyAgreement.PublicKey(x963Representation: publicKey)
            let prk521 = try P521.KeyAgreement.PrivateKey(x963Representation: keyTag)
            sharedSecret = try prk521.sharedSecretFromKeyAgreement(with: puk521)
        default: throw SecureAreaError("Unsupported curve \(curve)")
        }
        return sharedSecret
    }
    
    /// returns information about the key with the given key
    public func getKeyInfo(keyTag: Data, keyUnlockData: Data?) throws -> KeyInfo {
        guard let keyUnlockData, let jwkName = String(data: keyUnlockData, encoding: .utf8), let crv = try? CoseEcCurve.fromJwkName(jwkName) else {
            throw SecureAreaError("keyUnlockData error")
        }
        let publicKey: Data
        switch crv {
        case .P256:
            let signingKey = try P256.Signing.PrivateKey(x963Representation: keyTag)
            publicKey = signingKey.publicKey.x963Representation
        case .P384:
            let signingKey = try P384.Signing.PrivateKey(x963Representation: keyTag)
            publicKey = signingKey.publicKey.x963Representation
        case .P521:
            let signingKey = try P521.Signing.PrivateKey(x963Representation: keyTag)
            publicKey = signingKey.publicKey.x963Representation
        default: throw SecureAreaError("Unsupported curve \(crv)")
        }
        let keyInfo = KeyInfo(publicKey: publicKey, curve: crv)
        return keyInfo
    }
}
