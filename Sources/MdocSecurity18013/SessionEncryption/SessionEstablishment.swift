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
			do {
				return try CoseKey(data: eReaderKeyRawData)
			} catch {
				logger.error("Failed to create CoseKey: \(error)")
				return nil
			}
		} else { return nil }
	}
}

extension SessionEstablishment: CBORDecodable {
	public init(cbor: CBOR) throws(MdocValidationError) {
		guard case let .map(m) = cbor else { throw .invalidCbor("SessionEstablishment must be a CBOR map") }
		guard case let .byteString(bs) = m[.utf8String(CodingKeys.data.rawValue)] else { throw .missingField("SessionEstablishment", CodingKeys.data.rawValue) }
		data = bs
		if let eReaderKey = m[.utf8String(CodingKeys.eReaderKey.rawValue)] {
			guard case let .tagged(tag, value) = eReaderKey else { throw .invalidCbor("SessionEstablishment eReaderKey must be tagged") }
			guard tag == .encodedCBORDataItem else { throw .invalidCbor("SessionEstablishment eReaderKey tag must be encodedCBOR (24)") }
			guard case let .byteString(ebs) = value else { throw .invalidCbor("SessionEstablishment eReaderKey value must be byteString") }
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

