import Foundation
import CryptoKit
import MdocDataModel18013
import SwiftCBOR

struct MdocAuthentication {
    let transcript: SessionTranscript
    let otherKey: CoseKey
    let deviceKey: CoseKeyPrivate

    public var sessionTranscriptBytes: [UInt8] { transcript.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions()) }
	
    func makeMACKeyAggrementAndDeriveKey(deviceAuth: DeviceAuthentication) throws -> SymmetricKey? {
		guard let sharedKey = otherKey.makeEckaDHAgreement(with: deviceKey.getx963Representation()) else { logger.error("Error in ECKA key MAC agreement"); return nil} //.x963Representation)
		let symmetricKey = try SessionEncryption.HMACKeyDerivationFunction(sharedSecret: sharedKey, salt: sessionTranscriptBytes, info: "EMacKey".data(using: .utf8)!)
		return symmetricKey
	}
	
	func getDeviceAuthForTransfer(docType: String, deviceNameSpacesRawData: [UInt8]) throws -> DeviceAuth? {
		let da = DeviceAuthentication(sessionTranscript: transcript, docType: docType, deviceNameSpacesRawData: deviceNameSpacesRawData)
		let contentBytes = da.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions())
		let bUseDeviceSign = UserDefaults.standard.bool(forKey: "PreferDeviceSignature")
		let coseRes: Cose
		if bUseDeviceSign {
			coseRes = Cose.makeDetachedCoseSign1(payloadData: Data(contentBytes), deviceKey: deviceKey, alg: .es256)
		} else {
            // this is the preferred method
            guard let symmetricKey = try self.makeMACKeyAggrementAndDeriveKey(deviceAuth: da) else { return nil}
            coseRes = Cose.makeDetachedCoseMac0(payloadData: Data(contentBytes), key: symmetricKey, alg: .hmac256)
	    }
		return DeviceAuth(cose: coseRes)
	}
}