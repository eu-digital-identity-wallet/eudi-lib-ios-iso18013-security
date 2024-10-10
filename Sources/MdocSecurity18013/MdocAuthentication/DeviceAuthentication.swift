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
import SwiftCBOR
import MdocDataModel18013

/// Implementes the intermediate structure for DeviceAuthentication
///
/// This structure is not transfered, only computed
/// The mDL calculates this ephemeral MAC by performing KDF(ECDH(mDL private key, reader ephemeral public key)) and the mDL reader calculates this ephemeral MAC by performing KDF(ECDH(mDL public key, reader ephemeral private key)).
  public struct DeviceAuthentication: Sendable {
    let sessionTranscript: SessionTranscript
    let docType: String
    let deviceNameSpacesRawData: [UInt8] 
  }

  extension DeviceAuthentication: CBOREncodable {
      public func toCBOR(options: CBOROptions) -> CBOR {
          .array([.utf8String("DeviceAuthentication"), sessionTranscript.toCBOR(options: options), .utf8String(docType), deviceNameSpacesRawData.taggedEncoded])
      }
  }

public enum DeviceAuthMethod: String {
	case deviceSignature
	case deviceMac
}
