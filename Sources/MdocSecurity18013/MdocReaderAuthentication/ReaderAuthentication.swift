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

/// Implements the intermediate structure for reader authentication
///
/// This structure is not transfered, only computed
/// The mdoc calculates this ephemeral MAC by performing KDF(ECDH(mdoc private key, reader ephemeral public key)) and the mdoc reader calculates this ephemeral MAC by performing KDF(ECDH(mdoc public key, reader ephemeral private key)).
  public struct ReaderAuthentication: Sendable {
    let sessionTranscript: SessionTranscript
    let itemsRequestRawData: [UInt8] 
  }

  extension ReaderAuthentication: CBOREncodable {
      public func toCBOR(options: CBOROptions) -> CBOR {
          .array([.utf8String("ReaderAuthentication"), sessionTranscript.toCBOR(options: options), itemsRequestRawData.taggedEncoded])
      }

  }
