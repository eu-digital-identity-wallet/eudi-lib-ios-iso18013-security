import Foundation
import CryptoKit
import MdocDataModel18013
import SwiftCBOR

/// Implements mdoc authentication
/// 
/// The security objective of mdoc authentication is to prevent cloning of the mdoc and to mitigate man in the middle attacks.
/// Currently the mdoc side is implemented (generation of device-auth)
/// Initialized from the session trascript object, the device private key and the reader ephemeral public key 
/// 
/// ```swift
/// let mdocAuth = MdocAuthentication(transcript: sessionEncr.transcript, authKeys: authKeys)
/// ```
struct MdocAuthentication {
    let transcript: SessionTranscript
    let authKeys: CoseKeyExchange

    var sessionTranscriptBytes: [UInt8] { transcript.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions()) }
	
	/// Calculate the ephemeral MAC key, by performing ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman)
	/// The inputs shall be the SDeviceKey.Priv and EReaderKey.Pub for the mdoc and EReaderKey.Priv and SDeviceKey.Pub for the mdoc reader.
    func makeMACKeyAggrementAndDeriveKey(deviceAuth: DeviceAuthentication) throws -> SymmetricKey? {
		guard let sharedKey = authKeys.makeEckaDHAgreement() else { logger.error("Error in ECKA key MAC agreement"); return nil} //.x963Representation)
		let symmetricKey = try SessionEncryption.HMACKeyDerivationFunction(sharedSecret: sharedKey, salt: sessionTranscriptBytes, info: "EMacKey".data(using: .utf8)!)
		return symmetricKey
	}
	
	/// Generate a ``DeviceAuth`` structure used for mdoc-authentication
	/// - Parameters:
	///   - docType: docType of the document to authenticate
	///   - deviceNameSpacesRawData: device-name spaces raw data. Usually is a CBOR-encoded empty dictionary
	///   - bUseDeviceSign: Specify true for device authentication (false is default)
	/// - Returns: DeviceAuth instance
	public func getDeviceAuthForTransfer(docType: String, deviceNameSpacesRawData: [UInt8], bUseDeviceSign: Bool = false) throws -> DeviceAuth? {
		let da = DeviceAuthentication(sessionTranscript: transcript, docType: docType, deviceNameSpacesRawData: deviceNameSpacesRawData)
		let contentBytes = da.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions())
		let coseRes: Cose
		if bUseDeviceSign {
			coseRes = try Cose.makeDetachedCoseSign1(payloadData: Data(contentBytes), deviceKey: authKeys.privateKey, alg: .es256)
		} else {
            // this is the preferred method
            guard let symmetricKey = try self.makeMACKeyAggrementAndDeriveKey(deviceAuth: da) else { return nil}
            coseRes = Cose.makeDetachedCoseMac0(payloadData: Data(contentBytes), key: symmetricKey, alg: .hmac256)
	    }
		return DeviceAuth(cose: coseRes)
	}
}
