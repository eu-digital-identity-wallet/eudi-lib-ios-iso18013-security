import Foundation
import SwiftCBOR
import MdocDataModel18013

/// this is not transfered, only computed
/// The mDL calculates this ephemeral MAC by performing KDF(ECDH(mDL private key, reader ephemeral public key)) and the mDL reader calculates this ephemeral MAC by performing KDF(ECDH(mDL public key, reader ephemeral private key)).

  public struct ReaderAuthentication {
    let sessionTranscript: SessionTranscript
    let itemsRequestRawData: [UInt8] 
  }

  extension ReaderAuthentication: CBOREncodable {
      public func toCBOR(options: CBOROptions) -> CBOR {
          .array([.utf8String("ReaderAuthentication"), sessionTranscript.toCBOR(options: options), itemsRequestRawData.taggedEncoded])
      }

  }