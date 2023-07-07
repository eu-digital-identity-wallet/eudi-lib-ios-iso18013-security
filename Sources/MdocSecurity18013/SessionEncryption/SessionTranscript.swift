//
//  SessionTranscript.swift

import Foundation
import MdocDataModel18013
import SwiftCBOR

// SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]
public struct SessionTranscript {
	/// device engagement bytes (NOT tagged)
	let devEngBytes: [UInt8]
	/// reader key bytes ( NOT tagged)
	let eReaderKeyBytes: [UInt8]
	// handover object
	let handOver: CBOR
}

extension SessionTranscript: CBOREncodable {
	public func toCBOR(options: CBOROptions) -> CBOR {
		return .array([.byteString(devEngBytes).taggedEncoded, .byteString(eReaderKeyBytes).taggedEncoded, handOver])
	}
}
