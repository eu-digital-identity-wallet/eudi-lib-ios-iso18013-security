//  SessionEstablishment.swift

import Foundation
import SwiftCBOR
import Logging
import MdocDataModel18013

/// The mdoc reader creates the session establishment message.Contains the reader key and the encrypted mdoc request.
/// The mdoc uses the data from the session establishment message to derive the session keys and decrypt the mdoc request.
public struct SessionEstablishment {
	let eReaderKeyRawData: [UInt8]
	let data: [UInt8]
	
	enum CodingKeys: String, CodingKey {
		case eReaderKey
		case data
	}

	var eReaderKey: CoseKey? { CoseKey(data: eReaderKeyRawData) }
}

extension SessionEstablishment: CBORDecodable {
	public init?(cbor: CBOR) {
		guard case let .map(values) = cbor else { logger.error("Session establishment data must be a map"); return nil  }
		guard case let .byteString(bs) = values[CodingKeys.data] else { logger.error("Session establishment missing data"); return nil }
		data = bs
		guard case let .tagged(tag, value) = values[CodingKeys.eReaderKey] else { logger.error("Session establishment eReaderKey must be tagged"); return nil }
		guard tag == .encodedCBORDataItem else { logger.error("Session establishment eReaderKey tag must be encodedCBOR (24)"); return nil }
		guard case let .byteString(ebs) = value else { logger.error("eReaderKey value must be byteString"); return nil }
		eReaderKeyRawData = ebs
	}
}

extension SessionEstablishment: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
		var res = [CBOR:CBOR]()
		res[.utf8String(CodingKeys.eReaderKey.rawValue)] = eReaderKeyRawData.taggedEncoded
		res[.utf8String(CodingKeys.data.rawValue)] = .byteString(data)
		return .map(res)
	}
}

