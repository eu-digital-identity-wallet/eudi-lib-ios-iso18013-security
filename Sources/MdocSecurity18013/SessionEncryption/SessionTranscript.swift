 /*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

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
