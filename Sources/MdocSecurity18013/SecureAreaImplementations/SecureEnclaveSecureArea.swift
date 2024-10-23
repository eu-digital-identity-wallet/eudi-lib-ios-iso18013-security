//
//  SecureArea.swift
//  MdocSecurity18013
//
//  Created by ffeli on 22/10/2024.
//
import Foundation
import CryptoKit
import MdocDataModel18013
/// CryptoKit Secure Enclave secure area
///
/// SecureArea implemetion that uses iOS device’s Secure Enclave. It is a hardware-based key manager.
public actor SecureEnclaveSecureArea: SecureArea {
    /// default Elliptic Curve type
    public static var defaultEcCurve: CoseEcCurve { .P256 }
    /// make key and return key tag
    public func createKey(crv: CoseEcCurve, keyInfo: KeyInfo?) throws -> Data {
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
        let signingKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyTag)
        let signature = (try! signingKey.signature(for: dataToSign)).rawRepresentation
        return signature
    }
    
    /// make shared secret with other public key
    public func keyAgreement(keyTag: Data, publicKey: Data, keyUnlockData: Data?) throws -> SharedSecret {
        let puk256 = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        let prk256 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyTag)
        let sharedSecret = try prk256.sharedSecretFromKeyAgreement(with: puk256)
        return sharedSecret
    }
    
    /// returns information about the key with the given key
    public func getKeyInfo(keyTag: Data) throws -> KeyInfo {
       let prk256 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyTag)
        let keyInfo = KeyInfo(publicKey: prk256.publicKey.x963Representation)
        return keyInfo
    }
}
