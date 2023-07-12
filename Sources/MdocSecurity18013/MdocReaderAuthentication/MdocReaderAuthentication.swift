import Foundation
import CryptoKit
import MdocDataModel18013
import SwiftCBOR

/// Implements mdoc reader authentication
///
/// The data that the mdoc reader authenticates is the ReaderAuthentication structure
/// Currently the mdoc side is implemented (verification of reader-auth CBOR data)
struct MdocReaderAuthentication {
    let transcript: SessionTranscript
	
	/// Validate the reader auth structure contained in the the reader's initial message
	/// - Parameters:
	///   - readerAuthCBOR: An untagged COSE-Sign1 structure containing the signature
	///   - readerAuthCertificate: The reader auth certificate decoded from above reader-auth structure. Contains the mdoc reader public key
	///   - itemsRequestRawData: Reader's item request raw data
	/// - Returns: True if verification of reader auth succeeds.
	public func validateReaderAuth(readerAuthCBOR: CBOR, readerAuthCertificate: Data, itemsRequestRawData: [UInt8]) throws -> Bool {
		let ra = ReaderAuthentication(sessionTranscript: transcript, itemsRequestRawData: itemsRequestRawData)
        let contentBytes = ra.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions())
		guard let readerAuth = Cose(type: .sign1, cbor: readerAuthCBOR) else { return false }
        guard let publicKeyx963 = getPublicKeyx963(publicCertData: readerAuthCertificate)  else { return false }
        return try readerAuth.validateDetachedCoseSign1(payloadData: Data(contentBytes), publicKey_x963: publicKeyx963)
	}
}
