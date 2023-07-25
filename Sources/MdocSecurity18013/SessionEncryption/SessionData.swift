import Foundation
import MdocDataModel18013
import SwiftCBOR
import Logging

/// Message data transfered between mDL and mDL reader
public struct SessionData {
	
	public let data: [UInt8]?
	public let status: UInt64?
	
	enum CodingKeys: String, CodingKey {
		case data
		case status
	}

	public init(cipher_data: [UInt8]? = nil, status: UInt64? = nil) {
		self.data = cipher_data
		self.status = status
	}
}

extension SessionData: CBORDecodable {
	public init?(cbor: CBOR) {
		guard case let .map(values) = cbor else { logger.error("Session data must be a map"); return nil  }
		if case let .unsignedInt(s) = values[CodingKeys.status] { status = s } else { logger.info("SessionData: Missing status"); status = nil  }
		if case let .byteString(bs) = values[CodingKeys.data] { data = bs } else { logger.error("SessionData: Missing data"); data = nil  }
	}
}

extension SessionData: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
		var res = [CBOR:CBOR]()
		if let st = status { res[CBOR.utf8String(CodingKeys.status.rawValue)] = CBOR.unsignedInt(st) }
		if let d = data { res[CBOR.utf8String(CodingKeys.data.rawValue)] = CBOR.byteString(d) }
		return .map(res)
	}
}


