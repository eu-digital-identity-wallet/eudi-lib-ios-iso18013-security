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
import Logging
import CryptoKit
import MdocDataModel18013
import SwiftCBOR

/// Implements mdoc reader authentication
///
/// The data that the mdoc reader authenticates is the ReaderAuthentication structure
/// Currently the mdoc side is implemented (verification of reader-auth CBOR data)
public struct MdocReaderAuthentication: Sendable {

    let transcript: SessionTranscript

	/// Validate the reader auth structure contained in the the reader's initial message
	/// - Parameters:
	///   - readerAuthCBOR: An untagged COSE-Sign1 structure containing the signature
	///   - readerAuthCertificate: The reader auth certificate decoded from above
	///     reader-auth structure. Contains the mdoc reader public key
	///   - itemsRequestRawData: Reader's item request raw data
	/// - Returns: (True if verification of reader auth has valid signature, reason for certificate validation failure)
	public func validateReaderAuth(
		readerAuthCBOR: CBOR,
		readerAuthX5c: [Data],
		itemsRequestRawData: [UInt8],
		rootIaca: [x5chain]
	) throws -> (Bool, String?) {
		let readerAuthentication = ReaderAuthentication(
			sessionTranscript: transcript,
			itemsRequestRawData: itemsRequestRawData
		)
		let contentBytes = readerAuthentication.toCBOR(options: CBOROptions())
			.taggedEncoded
			.encode(options: CBOROptions())
		let secCerts = readerAuthX5c.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
		let hasMatchingCertificateCount = !secCerts.isEmpty && secCerts.count == readerAuthX5c.count
		guard hasMatchingCertificateCount else { return (false, "Invalid reader Auth Certificate") }
		guard let readerAuthCose = Cose(type: .sign1, cbor: readerAuthCBOR) else {
			return (false, "Invalid reader auth CBOR")
		}
		guard let readerCertificate = secCerts.first,
			  let readerPublicKeyX963 = SecurityHelpers.getPublicKeyx963(ref: readerCertificate) else {
			return (false, "Public key not found in certificate")
		}
		let isSignatureValid = try readerAuthCose.validateDetachedCoseSign1(
			payloadData: Data(contentBytes),
			publicKey_x963: readerPublicKeyX963
		)
		guard isSignatureValid else { return (false, "Reader auth signature validation failed") }
		let certificateValidation = SecurityHelpers.isMdocX5cValid(
			secCerts: secCerts,
			usage: .mdocReaderAuth,
			rootIaca: rootIaca
		)
		if !certificateValidation.isValid {
			let validationMessage = certificateValidation.validationMessages.joined(separator: "\n")
			logger.warning(Logger.Message(unicodeScalarLiteral: validationMessage))
		}
		let validationSummary = certificateValidation.validationMessages.joined(separator: "\n")
		return (isSignatureValid && certificateValidation.isValid, validationSummary)
	}

	public init(transcript: SessionTranscript) {
		self.transcript = transcript
	}
}
