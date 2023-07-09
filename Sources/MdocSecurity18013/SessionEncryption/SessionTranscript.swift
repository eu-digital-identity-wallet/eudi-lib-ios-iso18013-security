//
//  SessionTranscript.swift

import Foundation
import MdocDataModel18013
import SwiftCBOR

/// SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]
struct SessionTranscript {
	/// device engagement bytes (NOT tagged)
	let devEngBytes: [UInt8]
	/// reader key bytes ( NOT tagged)
	let eReaderKeyBytes: [UInt8]
	// handover object
	let handOver: CBOR
}

#if DEBUG
// initializer used for tests only
extension SessionTranscript: CBORDecodable {
	init?(cbor: CBOR) {
		guard case let .array(arr) = cbor, arr.count == 3 else { return nil }
		guard let d = arr[0].decodeTaggedBytes() else { return nil }
		guard let e = arr[1].decodeTaggedBytes() else { return nil }
		devEngBytes = d; eReaderKeyBytes = e; handOver = arr[2] 
	}
}
#endif

extension SessionTranscript: CBOREncodable {
	func toCBOR(options: CBOROptions) -> CBOR {
		return .array([devEngBytes.taggedEncoded, eReaderKeyBytes.taggedEncoded, handOver]).taggedEncoded
	}
}
