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

//  EckaDHAgreement.swift
import Foundation
import CryptoKit
import MdocDataModel18013

extension CoseKeyExchange {

	/// Computes a shared secret from the private key and the provided public key from another party.
	public func makeEckaDHAgreement(inSecureEnclave: Bool) -> SharedSecret? {
		var sharedSecret: SharedSecret?
		switch publicKey.crv {
		case .p256:
			guard let puk256 = try? P256.KeyAgreement.PublicKey(x963Representation: publicKey.getx963Representation()) else { return nil}
			if inSecureEnclave {
				guard let sOID = privateKey.secureEnclaveKeyID else { logger.error("Missing Private key Secure Enclave ID"); return nil }
				guard let prk256 = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: sOID) else { return nil}
				sharedSecret = try? prk256.sharedSecretFromKeyAgreement(with: puk256)
			} else {
				guard let prk256 = try? P256.KeyAgreement.PrivateKey(x963Representation: privateKey.getx963Representation()) else { return nil}
				sharedSecret = try? prk256.sharedSecretFromKeyAgreement(with: puk256)
			}
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
