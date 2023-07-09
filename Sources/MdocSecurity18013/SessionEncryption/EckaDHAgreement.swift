//
//  EckaDHAgreement.swift
import Foundation
import CryptoKit
import MdocDataModel18013

extension CoseKey {
	public func makeEckaDHAgreement(with privateKeyx963Representation: Data) -> SharedSecret? {
		var sharedSecret: SharedSecret?
		switch crv {
		case .p256:
			guard let publicKey = try? P256.KeyAgreement.PublicKey(x963Representation: getx963Representation()) else { return nil}
			guard let privateKey = try? P256.KeyAgreement.PrivateKey(x963Representation: privateKeyx963Representation) else { return nil}
			sharedSecret = try? privateKey.sharedSecretFromKeyAgreement(with: publicKey)
		case .p384:
			guard let publicKey = try? P384.KeyAgreement.PublicKey(x963Representation: getx963Representation()) else { return nil}
			guard let privateKey = try? P384.KeyAgreement.PrivateKey(x963Representation: privateKeyx963Representation) else { return nil}
			sharedSecret = try? privateKey.sharedSecretFromKeyAgreement(with: publicKey)
		case .p521:
			guard let publicKey = try? P521.KeyAgreement.PublicKey(x963Representation: getx963Representation()) else { return nil}
			guard let privateKey = try? P521.KeyAgreement.PrivateKey(x963Representation: privateKeyx963Representation) else { return nil}
			sharedSecret = try? privateKey.sharedSecretFromKeyAgreement(with: publicKey)
		}
		return sharedSecret
	}	
}
