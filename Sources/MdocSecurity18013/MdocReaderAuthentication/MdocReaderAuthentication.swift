import Foundation
import Logging
import CryptoKit
import MdocDataModel18013
import SwiftCBOR

/// Implements mdoc reader authentication
///
/// The data that the mdoc reader authenticates is the ReaderAuthentication structure
/// Currently the mdoc side is implemented (verification of reader-auth CBOR data)
public struct MdocReaderAuthentication {

    let transcript: SessionTranscript
	
	/// Validate the reader auth structure contained in the the reader's initial message
	/// - Parameters:
	///   - readerAuthCBOR: An untagged COSE-Sign1 structure containing the signature
	///   - readerAuthCertificate: The reader auth certificate decoded from above reader-auth structure. Contains the mdoc reader public key
	///   - itemsRequestRawData: Reader's item request raw data
	/// - Returns: True if verification of reader auth succeeds.
	public func validateReaderAuth(readerAuthCBOR: CBOR, readerAuthCertificate: Data, itemsRequestRawData: [UInt8], rootCerts: [SecCertificate]? = nil) throws -> Bool {
		let ra = ReaderAuthentication(sessionTranscript: transcript, itemsRequestRawData: itemsRequestRawData)
        let contentBytes = ra.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions())
		guard let sc = SecCertificateCreateWithData(nil, Data(readerAuthCertificate) as CFData) else { return false }
		guard let readerAuth = Cose(type: .sign1, cbor: readerAuthCBOR) else { return false }
        guard let publicKeyx963 = getPublicKeyx963(ref: sc) else { return false }
        let b1 = try readerAuth.validateDetachedCoseSign1(payloadData: Data(contentBytes), publicKey_x963: publicKeyx963)
		guard let rootCerts else { return b1 }
		let b2 = SecurityHelpers.isValidMdlPublicKey(secCert: sc, usage: .mdocReaderAuth, rootCerts: rootCerts)
		if !b2.isValid { logger.log(level: .info, Logger.Message(unicodeScalarLiteral: b2.reason ?? "")) }
		return b1 && b2.isValid
	}
	
	public init(transcript: SessionTranscript) {
		self.transcript = transcript
	}
}
