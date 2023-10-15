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
import Crypto
import MdocDataModel18013

extension Cose {

	/// Make an untagged COSE-Mac0 structure according to https://datatracker.ietf.org/doc/html/rfc8152#section-6.3 (How to Compute and Verify a MAC)
	/// - Parameters:
	///   - payloadData: The serialized content to be MACed
	///   - key: ECDH-agreed key
	///   - alg: MAC algorithm
	/// - Returns: A Cose structure with detached payload used for verification
	public static func makeDetachedCoseMac0(payloadData: Data, key: SymmetricKey, alg: Cose.MacAlgorithm) -> Cose {
		let coseIn = Cose(type: .mac0, algorithm: alg.rawValue, payloadData: payloadData)
		let dataToSign = coseIn.signatureStruct!
		// return COSE_MAC0 struct
		return Cose(type: .mac0, algorithm: alg.rawValue, signature: computeMACValue(dataToSign, key: key, alg: alg))
	}
	/// Computes a message authenticated code for the data
	/// - Parameters:
	///   - dataToAuthenticate: Data for which to compute the code
	///   - key: symmetric key
	///   - alg: HMAC algorithm variant
	/// - Returns: The message authenticated code
	public static func computeMACValue(_ dataToAuthenticate: Data, key: SymmetricKey, alg: Cose.MacAlgorithm) -> Data {
		let mac0Value: Data
		switch alg {
		case .hmac256:
            let hashCode = Crypto.HMAC<SHA256>.authenticationCode(for: dataToAuthenticate, using: key)
			mac0Value = hashCode.withUnsafeBytes{ (p: UnsafeRawBufferPointer) -> Data in  Data(p[0..<p.count]) }
		case .hmac384:
            let hashCode = Crypto.HMAC<SHA384>.authenticationCode(for: dataToAuthenticate, using: key)
			mac0Value = hashCode.withUnsafeBytes{ (p: UnsafeRawBufferPointer) -> Data in  Data(p[0..<p.count]) }
		case .hmac512:
            let hashCode = Crypto.HMAC<SHA512>.authenticationCode(for: dataToAuthenticate, using: key)
			mac0Value = hashCode.withUnsafeBytes{ (p: UnsafeRawBufferPointer) -> Data in  Data(p[0..<p.count]) }
		}
		return mac0Value
	}
}
