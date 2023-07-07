//  SessionEstablishment.swift

import Foundation
import SwiftCBOR
import Logging
import MdocDataModel18013

struct SessionEstablishment {
	let eReaderKey: CoseKey
	let data: [UInt8]
	
	enum CodingKeys: String, CodingKey {
		case eReaderKey
		case data
	}
}

extension SessionEstablishment: CBORDecodable {
	public init?(cbor: CBOR) {
		guard case let .map(values) = cbor else { logger.error("Session establishment data must be a map"); return nil  }
		guard case let .byteString(bs) = values[CodingKeys.data] else { logger.error("Session establishment missing data"); return nil }
		data = bs
		guard case let .tagged(tag, value) = values[CodingKeys.eReaderKey] else { logger.error("Session establishment eReaderKey must be tagged"); return nil }
		guard tag == .encodedCBORDataItem else { logger.error("Session establishment eReaderKey tag must be encodedCBOR (24)"); return nil }
		guard case let .byteString(eReaderKeyBytes) = value else { logger.error("eReaderKey value must be byteString"); return nil }
		guard let erk = CoseKey(data: eReaderKeyBytes) else { logger.error("eReaderKey could not be created from bytes"); return nil }
		eReaderKey = erk
	}
}

extension SessionEstablishment: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
		var res = [CBOR:CBOR]()
		res[.utf8String(CodingKeys.eReaderKey.rawValue)] = eReaderKey.taggedEncoded
		res[.utf8String(CodingKeys.data.rawValue)] = .byteString(data)
		return .map(res)
	}
}

