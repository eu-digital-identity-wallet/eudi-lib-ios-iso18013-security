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

import Foundation
import SwiftCBOR
import MdocDataModel18013

/// Implements the intermediate structure for reader authentication
///
/// This structure is not transfered, only computed
/// The mdoc calculates this ephemeral MAC by performing KDF(ECDH(mdoc private key, reader ephemeral public key)) and the mdoc reader calculates this ephemeral MAC by performing KDF(ECDH(mdoc public key, reader ephemeral private key)).
  public struct ReaderAuthentication {
    let sessionTranscript: SessionTranscript
    let itemsRequestRawData: [UInt8] 
  }

  extension ReaderAuthentication: CBOREncodable {
      public func toCBOR(options: CBOROptions) -> CBOR {
          .array([.utf8String("ReaderAuthentication"), sessionTranscript.toCBOR(options: options), itemsRequestRawData.taggedEncoded])
      }

  }
