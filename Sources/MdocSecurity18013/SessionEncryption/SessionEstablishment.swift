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

//  SessionEstablishment.swift

import Foundation
import SwiftCBOR
import Logging
import MdocDataModel18013
import OrderedCollections

/// The mdoc reader creates the session establishment message.Contains the reader key and the encrypted mdoc request.
/// The mdoc uses the data from the session establishment message to derive the session keys and decrypt the mdoc request.
public struct SessionEstablishment: Sendable {
	public var eReaderKeyRawData: [UInt8]?
	public let data: [UInt8]
	
	enum CodingKeys: String, CodingKey {
		case eReaderKey
		case data
	}
	public var eReaderKey: CoseKey? {
		if let eReaderKeyRawData {
			return CoseKey(data: eReaderKeyRawData) } else { return nil }
	}
}

extension SessionEstablishment: CBORDecodable {
	public init?(cbor: CBOR) {
		guard case let .map(m) = cbor else { logger.error("Session establishment data must be a map"); return nil  }
		guard case let .byteString(bs) = m[.utf8String(CodingKeys.data.rawValue)] else { logger.error("Session establishment missing data"); return nil }
		data = bs
		if let eReaderKey = m[.utf8String(CodingKeys.eReaderKey.rawValue)] {
			guard case let .tagged(tag, value) = eReaderKey else { logger.error("Session establishment eReaderKey must be tagged"); return nil }
			guard tag == .encodedCBORDataItem else { logger.error("Session establishment eReaderKey tag must be encodedCBOR (24)"); return nil }
			guard case let .byteString(ebs) = value else { logger.error("eReaderKey value must be byteString"); return nil }
			eReaderKeyRawData = ebs
		} else { eReaderKeyRawData = nil }
	}
}

extension SessionEstablishment: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
		var res = OrderedDictionary<CBOR, CBOR>()
		if let eReaderKeyRawData { res[.utf8String(CodingKeys.eReaderKey.rawValue)] = eReaderKeyRawData.taggedEncoded }
		res[.utf8String(CodingKeys.data.rawValue)] = .byteString(data)
		return .map(res)
	}
}

