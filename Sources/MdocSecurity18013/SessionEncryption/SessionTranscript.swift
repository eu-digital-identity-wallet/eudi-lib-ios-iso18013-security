//
//  SessionTranscript.swift

import Foundation
import MdocDataModel18013
import SwiftCBOR

/// SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]
public struct SessionTranscript {
	/// device engagement bytes (NOT tagged)
	let devEngRawData: [UInt8]
	/// reader key bytes ( NOT tagged)
	let eReaderRawData: [UInt8]
	// handover object
	let handOver: CBOR
}

#if DEBUG
// initializer used for tests only
extension SessionTranscript: CBORDecodable {
	public init?(cbor: CBOR) {
		guard case let .array(arr) = cbor, arr.count == 3 else { return nil }
		guard let d = arr[0].decodeTaggedBytes() else { return nil }
		guard let e = arr[1].decodeTaggedBytes() else { return nil }
		devEngRawData = d; eReaderRawData = e; handOver = arr[2] 
	}
}
#endif

extension SessionTranscript: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
		return .array([devEngRawData.taggedEncoded, eReaderRawData.taggedEncoded, handOver])
	}
}
