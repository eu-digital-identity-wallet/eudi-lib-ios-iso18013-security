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

//  SessionTranscript.swift

import Foundation
import MdocDataModel18013
import SwiftCBOR

/// SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]
public struct SessionTranscript {
	/// device engagement bytes (NOT tagged)
	let devEngRawData: [UInt8]?
	/// reader key bytes ( NOT tagged)
	let eReaderRawData: [UInt8]?
	// handover object
	let handOver: CBOR
		
	public init(devEngRawData: [UInt8]? = nil, eReaderRawData: [UInt8]? = nil, handOver: CBOR) {
		self.devEngRawData = devEngRawData
		self.eReaderRawData = eReaderRawData
		self.handOver = handOver
	}
}
#if DEBUG
// initializer used for tests only
extension SessionTranscript: CBORDecodable {
	public init?(cbor: CBOR) {
		guard case let .array(arr) = cbor, arr.count == 3 else { return nil }
		if let d = arr[0].decodeTaggedBytes() { devEngRawData = d } else { devEngRawData = nil }
		if let e = arr[1].decodeTaggedBytes() { eReaderRawData = e; } else { eReaderRawData = nil }
		handOver = arr[2]
	}
}
#endif

extension SessionTranscript: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
		return .array([devEngRawData?.taggedEncoded ?? CBOR.null, eReaderRawData?.taggedEncoded ?? CBOR.null, handOver])
	}
}
