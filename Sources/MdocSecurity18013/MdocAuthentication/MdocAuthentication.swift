/*
Copyright (c) 2026 European Commission

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
import SwiftCBOR

/// Implements mdoc authentication
///
/// The security objective of mdoc authentication is to prevent cloning of the
/// mdoc and to mitigate man in the middle attacks.
/// Currently the mdoc side is implemented (generation of device-auth)
/// Initialized from the session transcript object, the device private key and the reader ephemeral public key
///
/// ```swift
/// let mdocAuth = MdocAuthentication(transcript: sessionEncr.transcript, authKeys: authKeys)
/// ```
public struct MdocAuthentication: Sendable {
    let sessionTranscript: SessionTranscript
    let authKeys: CoseKeyExchange
	var sessionTranscriptBytes: [UInt8] {
		sessionTranscript.toCBOR(options: CBOROptions())
			.taggedEncoded
			.encode(options: CBOROptions())
	}

	public init(sessionTranscript: SessionTranscript, authKeys: CoseKeyExchange) {
		self.sessionTranscript = sessionTranscript
		self.authKeys = authKeys
	}

	/// Calculate the ephemeral MAC key, by performing ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman)
	/// The inputs shall be the SDeviceKey.Priv and EReaderKey.Pub for the mdoc
	/// and EReaderKey.Priv and SDeviceKey.Pub for the mdoc reader.
    func makeMACKeyAggrementAndDeriveKey(deviceAuth: DeviceAuthentication, unlockData: Data? = nil, authenticationContext: ThreadSafeAuthContext) async throws -> SymmetricKey? {
		let sharedKey = try await authKeys.makeEckaDHAgreement(unlockData: unlockData, authenticationContext: authenticationContext)
		let emacInfo = "EMacKey".data(using: .utf8)!
		let symmetricKey = try SessionEncryption.HMACKeyDerivationFunction(
			sharedSecret: sharedKey,
			salt: sessionTranscriptBytes,
			info: emacInfo
		)
		return symmetricKey
	}

	/// Generate a ``DeviceAuth`` structure used for mdoc-authentication
	/// - Parameters:
	///   - docType: docType of the document to authenticate
	///   - deviceNameSpacesRawData: device-name spaces raw data. Usually is a CBOR-encoded empty dictionary
	///   - dauthMethod: Device signature or device MAC authentication
	///   - signatureAlgorithm: COSE algorithm for device signatures; defaults to ES256 and is ignored for device MACs
	/// - Returns: DeviceAuth instance
    public func getDeviceAuthForTransfer(
        docType: String,
        dauthMethod: DeviceAuthMethod,
        signatureAlgorithm: Cose.VerifyAlgorithm = .es256,
        deviceNameSpaces: DeviceNameSpaces?,
        unlockData: Data?,
        authenticationContext: ThreadSafeAuthContext
    ) async throws -> DeviceAuth? {
		let deviceAuthentication = DeviceAuthentication(
			sessionTranscript: sessionTranscript,
			docType: docType,
			deviceNameSpaces: deviceNameSpaces
		)
		let contentBytes = deviceAuthentication.toCBOR(options: CBOROptions())
			.taggedEncoded
			.encode(options: CBOROptions())
		let detachedAuthCose: Cose
		if dauthMethod == .deviceSignature {
			detachedAuthCose = try await Cose.makeDetachedCoseSign1(
				payloadData: Data(contentBytes),
				deviceKey: authKeys.privateKey,
				alg: signatureAlgorithm,
				unlockData: unlockData,
				authenticationContext: authenticationContext
			)
		} else {
            // this is the preferred method
			guard let symmetricKey = try await self.makeMACKeyAggrementAndDeriveKey(deviceAuth: deviceAuthentication, unlockData: unlockData, authenticationContext: authenticationContext) else {
				return nil
			}
			detachedAuthCose = Cose.makeDetachedCoseMac0(
				payloadData: Data(contentBytes),
				key: symmetricKey,
				alg: .hmac256
			)
	    }
		return DeviceAuth(coseMacOrSignature: detachedAuthCose)
	}
}
