 /*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

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
