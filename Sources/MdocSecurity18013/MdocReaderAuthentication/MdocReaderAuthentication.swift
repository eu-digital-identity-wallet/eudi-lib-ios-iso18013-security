import Foundation
import CryptoKit
import MdocDataModel18013
import SwiftCBOR

struct MdocReaderAuthentication {
    let transcript: SessionTranscript
   	
	public func validateReaderAuth(readerAuthCBOR: CBOR, readerAuthCertificate: Data, itemsRequestRawData: [UInt8]) throws -> Bool {
		let ra = ReaderAuthentication(sessionTranscript: transcript, itemsRequestRawData: itemsRequestRawData)
        let contentBytes = ra.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions())
		guard let readerAuth = Cose(type: .sign1, cbor: readerAuthCBOR) else { return false }
        guard let publicKeyx963 = getPublicKeyx963(publicCertData: readerAuthCertificate)  else { return false }
        return try readerAuth.validateDetachedCoseSign1(payloadData: Data(contentBytes), publicKey_x963: publicKeyx963)
	}
}