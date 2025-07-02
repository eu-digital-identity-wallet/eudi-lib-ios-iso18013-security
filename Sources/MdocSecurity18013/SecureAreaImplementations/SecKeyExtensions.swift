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

import CryptoKit
import Security
import Foundation

extension SecureEnclave.P256.Signing.PrivateKey {
	func toSecKey() throws -> SecKey {
		var errorQ: Unmanaged<CFError>?
		guard let sf = SecKeyCreateWithData(Data() as NSData, [
			kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
			kSecAttrKeyClass: kSecAttrKeyClassPrivate,
			kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
			"toid": dataRepresentation
		] as NSDictionary, &errorQ) else { throw errorQ!.takeRetainedValue() as Error }
		return sf
	}
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey {
    func toSecKey() throws -> SecKey {
        var errorQ: Unmanaged<CFError>?
        guard let sf = SecKeyCreateWithData(Data() as NSData, [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            "toid": dataRepresentation
        ] as NSDictionary, &errorQ) else { throw errorQ!.takeRetainedValue() as Error }
        return sf
    }
}

extension P256.Signing.PrivateKey {
	func toSecKey() throws -> SecKey {
		var error: Unmanaged<CFError>?
		guard let privateKey = SecKeyCreateWithData(x963Representation as NSData, [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as NSDictionary, &error) else {
			throw error!.takeRetainedValue() as Error
		}
		return privateKey
	}
}

extension P256.KeyAgreement.PrivateKey {
    public func toSecKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(x963Representation as NSData, [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as NSDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }
}

extension P384.Signing.PrivateKey {
    func toSecKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(x963Representation as NSData, [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as NSDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }
}

extension P521.Signing.PrivateKey {
    func toSecKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(x963Representation as NSData, [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as NSDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }
}

extension SecKey {

    public enum KeyType {
        case rsa
        case ellipticCurve
        var secAttrKeyTypeValue: CFString {
            switch self {
            case .rsa:
                return kSecAttrKeyTypeRSA
            case .ellipticCurve:
                return kSecAttrKeyTypeECSECPrimeRandom
            }
        }
    }

    /// Creates a random key.
    /// Elliptic curve bits options are: 192, 256, 384, or 521.
    public static func createRandomKey(type: KeyType, bits: Int) throws -> SecKey {
        var error: Unmanaged<CFError>?
        let keyO = SecKeyCreateRandomKey([
            kSecAttrKeyType: type.secAttrKeyTypeValue,
            kSecAttrKeySizeInBits: NSNumber(integerLiteral: bits),
        ] as CFDictionary, &error)
        // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_as_data
        if let error = error?.takeRetainedValue() { throw error }
        guard let key = keyO else { throw NSError(domain: "SecKey", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create random key"]) }
        return key
    }

    /// Gets the public key from a key pair.
    public func publicKey() throws -> SecKey {
        let publicKeyO = SecKeyCopyPublicKey(self)
        guard let publicKey = publicKeyO else { throw NSError(domain: "SecKey", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create public key"]) }
        return publicKey
    }

    /// Exports a key.
    /// RSA keys are returned in PKCS #1 / DER / ASN.1 format.
    /// EC keys are returned in ANSI X9.63 format.
    public func externalRepresentation() throws -> Data {
        var error: Unmanaged<CFError>?
        let dataO = SecKeyCopyExternalRepresentation(self, &error)
        if let error = error?.takeRetainedValue() { throw error }
        guard let data = dataO else { throw NSError(domain: "SecKey", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create external representation"]) }
        return data as Data
    }

        // Self must be the public key returned by publicKey().
    // Algorithm should be SecKeyAlgorithm.rsaEncryption* or .eciesEncryption*
    public func encrypt(algorithm: SecKeyAlgorithm, plaintext: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        let ciphertextO = SecKeyCreateEncryptedData(self, algorithm,
            plaintext as CFData, &error)
        if let error = error?.takeRetainedValue() { throw error }
        guard let ciphertext = ciphertextO else { throw NSError(domain: "SecKey", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create cipher text"]) }
        return ciphertext as Data
    }

    // Self must be the private/public key pair returned by createRandomKey().
    // Algorithm should be SecKeyAlgorithm.rsaEncryption* or .eciesEncryption*
    public func decrypt(algorithm: SecKeyAlgorithm, ciphertext: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        let plaintextO = SecKeyCreateDecryptedData(self, algorithm,
            ciphertext as CFData, &error)
        if let error = error?.takeRetainedValue() { throw error }
        guard let plaintext = plaintextO else { throw NSError(domain: "SecKey", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create plain text"]) }
        return plaintext as Data
    }
}