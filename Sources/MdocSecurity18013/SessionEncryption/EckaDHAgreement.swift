//
//  EckaDHAgreement.swift
import Foundation
import CryptoKit
import MdocDataModel18013

extension CoseKeyExchange {

	/// Computes a shared secret from the private key and the provided public key from another party.
	public func makeEckaDHAgreement() -> SharedSecret? {
		var sharedSecret: SharedSecret?
		switch publicKey.crv {
		case .p256:
			guard let puk256 = try? P256.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation()) else { return nil}
			guard let prk256 = try? P256.KeyAgreement.PrivateKey(x963Representation: privateKey.getx963Representation()) else { return nil}
			sharedSecret = try? prk256.sharedSecretFromKeyAgreement(with: puk256)
		case .p384:
			guard let puk384 = try? P384.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation()) else { return nil}
			guard let prk384 = try? P384.KeyAgreement.PrivateKey(x963Representation: privateKey.getx963Representation()) else { return nil}
			sharedSecret = try? prk384.sharedSecretFromKeyAgreement(with: puk384)
		case .p521:
			guard let puk521 = try? P521.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation()) else { return nil}
			guard let prk521 = try? P521.KeyAgreement.PrivateKey(x963Representation: privateKey.getx963Representation()) else { return nil}
			sharedSecret = try? prk521.sharedSecretFromKeyAgreement(with: puk521)
		}
		return sharedSecret
	}	
}
