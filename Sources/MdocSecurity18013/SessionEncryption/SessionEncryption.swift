import Foundation
import CryptoKit
import MdocDataModel18013
import SwiftCBOR

public struct SessionEncryption {
	let sessionRole: SessionRole
	public var sessionCounter: UInt32 = 1
	var errorCode: UInt?
	static let IDENTIFIER0: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	static let IDENTIFIER1: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
	var encryptionIdentifier: [UInt8] { sessionRole == .reader ? Self.IDENTIFIER0 : Self.IDENTIFIER1 }
	var decryptionIdentifier: [UInt8] { sessionRole == .reader ? Self.IDENTIFIER1 : Self.IDENTIFIER0 }
	let privateKey: CoseKeyPrivate
	let otherKey: CoseKey
	var deviceEngagementRawData: [UInt8]
	let eReaderKeyRawData: [UInt8]
	let handOver: CBOR
	
	init?(se: SessionEstablishment, de: DeviceEngagement, handOver: CBOR) {
		sessionRole = .mDL
		deviceEngagementRawData = de.encode(options: CBOROptions())
		guard let pk = de.privateKey else { logger.error("Device engagement for mDL must have the private key"); return nil}
		privateKey = pk
		self.eReaderKeyRawData = se.eReaderKeyRawData
		guard let ok = se.eReaderKey  else { logger.error("Could not decode ereader key"); return nil}
		self.otherKey = ok
		self.handOver = handOver
	}
	
	func makeNonce(_ counter: UInt32, isEncrypt: Bool) throws -> AES.GCM.Nonce {
		var dataNonce = Data()
		let identifier = isEncrypt ? encryptionIdentifier : decryptionIdentifier
		dataNonce.append(Data(identifier))
		dataNonce.append(Data(counter.byteArrayLittleEndian))
		let nonce = try AES.GCM.Nonce(data: dataNonce)
		return nonce
	}
	
	public static func HMACKeyDerivationFunction(sharedSecret: SharedSecret, salt: [UInt8], info: Data) throws -> SymmetricKey {
		let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
		return symmetricKey
	}
	
	/// encrypt data using current nonce
	mutating func encrypt(_ data: [UInt8]) throws -> [UInt8]? {
		let nonce = try makeNonce(sessionCounter, isEncrypt: true) 
		guard let symmetricKeyForEncrypt = try makeKeyAgreementAndDeriveKey(saltTranscript: sessionTranscriptBytes, isEncrypt: true) else { return nil }
		guard let encryptedContent = try AES.GCM.seal(data, using: symmetricKeyForEncrypt, nonce: nonce).combined else { return nil }
		if sessionRole == .mDL { sessionCounter += 1 }
		return [UInt8](encryptedContent.dropFirst(12))
	}
	
	/// Generates an ephemeral key agreement key and the performs key agreement to get the shared secret and derive the symmetric encryption key.
	mutating func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8]? {
		let nonce = try makeNonce(sessionCounter, isEncrypt: false) 
		guard let sealedBox = try? AES.GCM.SealedBox(combined: nonce + ciphertext) else { return nil }
		guard let symmetricKeyForDecrypt = try makeKeyAgreementAndDeriveKey(saltTranscript: sessionTranscriptBytes, isEncrypt: false) else { return nil }
		let decryptedContent = try AES.GCM.open(sealedBox, using: symmetricKeyForDecrypt) 
		return [UInt8](decryptedContent)
	}
	
	//   SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]
	public var sessionTranscriptBytes: [UInt8] {
		let transcript = SessionTranscript(devEngBytes: deviceEngagementRawData, eReaderKeyBytes: eReaderKeyRawData, handOver: handOver)
		return transcript.encode(options: CBOROptions())
	}
	
	func getInfo(isEncrypt: Bool) -> String { isEncrypt ? (sessionRole == .mDL ? "SKDevice" : "SKReader") : (sessionRole == .mDL ? "SKReader" : "SKDevice") }
	
	func makeKeyAgreementAndDeriveKey(saltTranscript: [UInt8], isEncrypt: Bool) throws -> SymmetricKey?  {
		guard let sharedKey = otherKey.makeEckaDHAgreement(with: privateKey.getx963Representation()) else { logger.error("Error in ECKA key agreement"); return nil} //.x963Representation)
		let symmetricKey = try Self.HMACKeyDerivationFunction(sharedSecret: sharedKey, salt: saltTranscript, info: getInfo(isEncrypt: isEncrypt).data(using: .utf8)!)
		return symmetricKey
	}
}

