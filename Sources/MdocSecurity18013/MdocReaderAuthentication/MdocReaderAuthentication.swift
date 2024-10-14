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
	///   - readerAuthCertificate: The reader auth certificate decoded from above reader-auth structure. Contains the mdoc reader public key
	///   - itemsRequestRawData: Reader's item request raw data
	/// - Returns: (True if verification of reader auth has valid signature, reason for certificate validation failure)
	public func validateReaderAuth(readerAuthCBOR: CBOR, readerAuthX5c: [Data], itemsRequestRawData: [UInt8], rootCerts: [SecCertificate]? = nil) throws -> (Bool, String?) {
		let ra = ReaderAuthentication(sessionTranscript: transcript, itemsRequestRawData: itemsRequestRawData)
		let contentBytes = ra.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions())
		let secCerts = readerAuthX5c.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
		guard secCerts.count > 0, secCerts.count == readerAuthX5c.count else { return (false, "Invalid reader Auth Certificate") }
		guard let readerAuth = Cose(type: .sign1, cbor: readerAuthCBOR) else { return (false, "Invalid reader auth CBOR") }
		guard let publicKeyx963 = SecurityHelpers.getPublicKeyx963(ref: secCerts.last!) else { return (false, "Public key not found in certificate") }
		let b1 = try readerAuth.validateDetachedCoseSign1(payloadData: Data(contentBytes), publicKey_x963: publicKeyx963)
		guard b1 else { return (false, "Reader auth signature validation failed") }
		let b2 = SecurityHelpers.isMdocX5cValid(secCerts: secCerts, usage: .mdocReaderAuth, rootCerts: rootCerts ?? [])
		if !b2.isValid { logger.warning(Logger.Message(unicodeScalarLiteral: b2.validationMessages.joined(separator: "\n"))) }
		return (b1, b2.validationMessages.joined(separator: "\n"))
	}
	
	public init(transcript: SessionTranscript) {
		self.transcript = transcript
	}
}
