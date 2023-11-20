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

import Foundation
import CryptoKit
import MdocDataModel18013

extension Cose {
	public static func makeDetachedCoseSign1(payloadData: Data, deviceKey: CoseKeyPrivate, alg: Cose.VerifyAlgorithm) throws-> Cose {
		return try makeDetachedCoseSign1(payloadData: payloadData, deviceKey_x963: deviceKey.getx963Representation(), alg: alg)
	}
	
	/// Create a detached COSE-Sign1 structure according to https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
	/// - Parameters:
	///   - payloadData: Payload to be signed
	///   - deviceKey_x963: static device private key (encoded with ANSI x.963)
	///   - alg: The algorithm to sign with
	/// - Returns: a detached COSE-Sign1 structure
	public static func makeDetachedCoseSign1(payloadData: Data, deviceKey_x963: Data, alg: Cose.VerifyAlgorithm) throws -> Cose {
		let coseIn = Cose(type: .sign1, algorithm: alg.rawValue, payloadData: payloadData)
		let dataToSign = coseIn.signatureStruct!
		// return COSE_SIGN1 struct
		return Cose(type: .sign1, algorithm: alg.rawValue, signature: try computeSignatureValue(dataToSign, deviceKey_x963: deviceKey_x963, alg: alg))
	}
	
	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of the provide data over an elliptic curve. Apple Crypto implementation is used
	/// - Parameters:
	///   - dataToSign: Data to create the signature for (payload)
	///   - deviceKey_x963: x963 representation of the private key
	///   - alg: ``MdocDataModel18013/Cose.VerifyAlgorithm``
	/// - Returns: The signature corresponding to the data
	public static func computeSignatureValue(_ dataToSign: Data, deviceKey_x963: Data, alg: Cose.VerifyAlgorithm) throws -> Data {
		let sign1Value: Data
		switch alg {
		case .es256:
			let signingKey = try P256.Signing.PrivateKey(x963Representation: deviceKey_x963)
			sign1Value = (try! signingKey.signature(for: dataToSign)).rawRepresentation
		case .es384:
			let signingKey = try P384.Signing.PrivateKey(x963Representation: deviceKey_x963)
			sign1Value = (try! signingKey.signature(for: dataToSign)).rawRepresentation
		case .es512:
			let signingKey = try P521.Signing.PrivateKey(x963Representation: deviceKey_x963)
			sign1Value = (try! signingKey.signature(for: dataToSign)).rawRepresentation
		}
		return sign1Value
	}
	
	
	/// Validate (verify) a detached COSE-Sign1 structure according to https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
	/// - Parameters:
	///   - payloadData: Payload data signed
	///   - publicKey_x963: public key corresponding the private key used to sign the data
	/// - Returns: True if validation of signature succeeds
	public func validateDetachedCoseSign1(payloadData: Data, publicKey_x963: Data) throws -> Bool {
		let b: Bool
		guard type == .sign1 else { logger.error("Cose must have type sign1"); return false}
		guard let verifyAlgorithm = verifyAlgorithm else { logger.error("Cose signature algorithm not found"); return false}
		let coseWithPayload = Cose(other: self, payloadData: payloadData)
		guard let signatureStruct = coseWithPayload.signatureStruct else { logger.error("Cose signature struct cannot be computed"); return false}
		switch verifyAlgorithm {
		case .es256:
			let signingPubKey = try P256.Signing.PublicKey(x963Representation: publicKey_x963)
			let ecdsa_signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
			b = signingPubKey.isValidSignature(ecdsa_signature, for: signatureStruct)
		case .es384:
			let signingPubKey = try P384.Signing.PublicKey(x963Representation: publicKey_x963)
			let ecdsa_signature = try P384.Signing.ECDSASignature(rawRepresentation: signature)
			b = signingPubKey.isValidSignature(ecdsa_signature, for: signatureStruct)
		case .es512:
			let signingPubKey = try P521.Signing.PublicKey(x963Representation: publicKey_x963)
			let ecdsa_signature = try P521.Signing.ECDSASignature(rawRepresentation: signature)
			b = signingPubKey.isValidSignature(ecdsa_signature, for: signatureStruct)
		}
		return b
	}
}
