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
