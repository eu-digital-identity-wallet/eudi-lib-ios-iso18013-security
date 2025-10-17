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
import MdocDataModel18013
import SwiftCBOR
import Logging
import OrderedCollections

/// Message data transfered between mDL and mDL reader
public struct SessionData: Sendable {

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
	public init(cbor: CBOR) throws(MdocValidationError) {
		guard case let .map(values) = cbor else { throw .invalidCbor("SessionData must be a CBOR map") }
		if case let .unsignedInt(s) = values[.utf8String(CodingKeys.status.rawValue)] { status = s } else { logger.info("SessionData: Missing status"); status = nil  }
		if case let .byteString(bs) = values[.utf8String(CodingKeys.data.rawValue)] { data = bs } else { logger.error("SessionData: Missing data"); data = nil  }
	}
}

extension SessionData: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
		var res = OrderedDictionary<CBOR, CBOR>()
		if let st = status { res[CBOR.utf8String(CodingKeys.status.rawValue)] = CBOR.unsignedInt(st) }
		if let d = data { res[CBOR.utf8String(CodingKeys.data.rawValue)] = CBOR.byteString(d) }
		return .map(res)
	}
}


