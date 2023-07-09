import Foundation
import SwiftCBOR
import MdocDataModel18013

/// this is not transfered, only computed
/// The mDL calculates this ephemeral MAC by performing KDF(ECDH(mDL private key, reader ephemeral public key)) and the mDL reader calculates this ephemeral MAC by performing KDF(ECDH(mDL public key, reader ephemeral private key)).

  public struct DeviceAuthentication {
    let sessionTranscript: SessionTranscript
    let docType: String
    let deviceNameSpacesRawData: [UInt8] 
  }

  extension DeviceAuthentication: CBOREncodable {
      public func toCBOR(options: CBOROptions) -> CBOR {
          .array([.utf8String("DeviceAuthentication"), sessionTranscript.toCBOR(options: options), .utf8String(docType), deviceNameSpacesRawData.taggedEncoded])
      }

  }