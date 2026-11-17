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

    /// Authentication failures are fatal, independently of certificate-trust policy.
    public enum ReaderAuthenticationError: Error, LocalizedError, Equatable {
        case invalidCertificate
        case invalidStructure
        case unsupportedAlgorithm
        case missingPublicKey
        case invalidSignature

        public var errorDescription: String? {
            switch self {
            case .invalidCertificate: "Invalid reader authentication certificate chain"
            case .invalidStructure: "Invalid reader authentication COSE-Sign1 structure"
            case .unsupportedAlgorithm: "Unsupported reader authentication signature algorithm"
            case .missingPublicKey: "Public key not found in reader authentication certificate"
            case .invalidSignature: "Reader authentication signature validation failed"
            }
        }
    }

    /// Authenticates the reader's request, then evaluates certificate-chain trust.
    /// - Parameters:
    ///   - readerAuthCBOR: An untagged, detached COSE-Sign1 structure.
    ///   - readerAuthX5c: DER certificate chain with the signing certificate first.
    ///   - itemsRequestRawData: Original bytes of the reader's items request.
    ///   - trustValidator: Certificate-chain trust evaluator.
    /// - Returns: Certificate trust and its failure reason, only after signature verification succeeds.
    /// - Throws: `ReaderAuthenticationError` for malformed authentication data or an invalid signature.
    ///   Callers must treat these errors as fatal under every trust policy. Only a returned
    ///   `false` trust result may be downgraded to a warning.
	public func validateReaderAuth(
		readerAuthCBOR: CBOR,
		readerAuthX5c: [Data],
		itemsRequestRawData: [UInt8],
        trustValidator: (any CertificateTrustValidator)
	) async throws -> (Bool, String?) {
		let readerAuthentication = ReaderAuthentication(
			sessionTranscript: transcript,
			itemsRequestRawData: itemsRequestRawData
		)
		let contentBytes = readerAuthentication.toCBOR(options: CBOROptions())
			.taggedEncoded
			.encode(options: CBOROptions())
		let secCerts = readerAuthX5c.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
		let hasMatchingCertificateCount = !secCerts.isEmpty && secCerts.count == readerAuthX5c.count
		guard hasMatchingCertificateCount else { throw ReaderAuthenticationError.invalidCertificate }
		guard case let .array(fields) = readerAuthCBOR, fields.count == 4,
              case let .byteString(protectedBytes) = fields[0],
              case .map = fields[1], case .null = fields[2],
              let decodedHeaders = try? CBOR.decode(protectedBytes),
              case let .map(headers) = decodedHeaders,
              let readerAuthCose = Cose(type: .sign1, cbor: readerAuthCBOR) else {
            throw ReaderAuthenticationError.invalidStructure
        }
        // The model's algorithm accessor does not distinguish positive and negative integers.
        guard case let .negativeInt(algorithm) = headers[.unsignedInt(1)],
              Cose.VerifyAlgorithm(rawValue: algorithm) != nil else {
            throw ReaderAuthenticationError.unsupportedAlgorithm
        }
		guard let readerCertificate = secCerts.first,
			  let readerPublicKeyX963 = SecurityHelpers.getPublicKeyx963(ref: readerCertificate) else {
			throw ReaderAuthenticationError.missingPublicKey
		}
        let isSignatureValid: Bool
        do {
            isSignatureValid = try readerAuthCose.validateDetachedCoseSign1(
                payloadData: Data(contentBytes),
                publicKey_x963: readerPublicKeyX963
            )
        } catch {
            // Malformed signatures and incompatible keys are authentication failures too.
            throw ReaderAuthenticationError.invalidSignature
        }
        guard isSignatureValid else { throw ReaderAuthenticationError.invalidSignature }
        return await trustValidator.validateCertTrustPath(chain: readerAuthX5c)
	}

	public init(transcript: SessionTranscript) {
		self.transcript = transcript
	}
}
