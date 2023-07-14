import Foundation
import CryptoKit
import MdocDataModel18013
import SwiftCBOR

/// Session encryption uses standard ephemeral key ECDH to establish session keys for authenticated symmetric encryption.
/// The ``SessionEncryption`` struct implements session encryption (for the mDoc currently)
/// It is initialized from a) the session establishment data received from the mdoc reader, b) the device engagement data generated from the mdoc and c) the handover data.
/// 
/// ```swift
/// var se = SessionEncryption(se: sessionEstablishmentObject, de: deviceEngagementObject, handOver: handOverObject)
/// ```
public struct SessionEncryption {
	let sessionRole: SessionRole
	public var sessionCounter: UInt32 = 1
	var errorCode: UInt?
	static let IDENTIFIER0: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	static let IDENTIFIER1: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
	var encryptionIdentifier: [UInt8] { sessionRole == .reader ? Self.IDENTIFIER0 : Self.IDENTIFIER1 }
	var decryptionIdentifier: [UInt8] { sessionRole == .reader ? Self.IDENTIFIER1 : Self.IDENTIFIER0 }
	let sessionKeys: CoseKeyExchange
	var deviceEngagementRawData: [UInt8]
	let eReaderKeyRawData: [UInt8]
	let handOver: CBOR
	
	/// Initialization of session encryption for the mdoc
	/// - Parameters:
	///   - se: session establishment data from the mdoc reader
	///   - de: device engagement created by the mdoc
	///   - handOver: handover object according to the transfer protocol
	init?(se: SessionEstablishment, de: DeviceEngagement, handOver: CBOR) {
		sessionRole = .mdoc
		deviceEngagementRawData = de.encode(options: CBOROptions())
		guard let pk = de.privateKey else { logger.error("Device engagement for mdoc must have the private key"); return nil}
		self.eReaderKeyRawData = se.eReaderKeyRawData
		guard let ok = se.eReaderKey  else { logger.error("Could not decode ereader key"); return nil}
		sessionKeys = CoseKeyExchange(publicKey: ok, privateKey: pk)
		self.handOver = handOver
	}
	
	/// Make nonce function to initialize the encryption or decryption
	///
	/// - Parameters:
	///   - counter: The message counter value shall be a 4-byte big-endian unsigned integer. For the first encryption with a session key, the message counter shall be set to 1. Before each following encryption with the same key, the message counter value shall be increased by 1
	///   - isEncrypt: is for encrypt?
	/// - Returns: The IV (Initialization Vector) used for the encryption.
	func makeNonce(_ counter: UInt32, isEncrypt: Bool) throws -> AES.GCM.Nonce {
		var dataNonce = Data()
		let identifier = isEncrypt ? encryptionIdentifier : decryptionIdentifier
		dataNonce.append(Data(identifier))
		dataNonce.append(Data(counter.byteArrayLittleEndian))
		let nonce = try AES.GCM.Nonce(data: dataNonce)
		return nonce
	}
	
	/// computation of HKDF symmetric key 
	static func HMACKeyDerivationFunction(sharedSecret: SharedSecret, salt: [UInt8], info: Data) throws -> SymmetricKey {
		let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
		return symmetricKey
	}
	
	/// encrypt data using current nonce as described in 9.1.1.5 Cryptographic operations
	mutating func encrypt(_ data: [UInt8]) throws -> [UInt8]? {
		let nonce = try makeNonce(sessionCounter, isEncrypt: true)
		guard let symmetricKeyForEncrypt = try makeKeyAgreementAndDeriveSessionKey(isEncrypt: true) else { return nil }
		guard let encryptedContent = try AES.GCM.seal(data, using: symmetricKeyForEncrypt, nonce: nonce).combined else { return nil }
		if sessionRole == .mdoc { sessionCounter += 1 }
		return [UInt8](encryptedContent.dropFirst(12))
	}
	
	/// decryptes cipher data using the symmetric key
	mutating func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8]? {
		let nonce = try makeNonce(sessionCounter, isEncrypt: false)
		let sealedBox = try AES.GCM.SealedBox(combined: nonce + ciphertext)
		guard let symmetricKeyForDecrypt = try makeKeyAgreementAndDeriveSessionKey(isEncrypt: false) else { return nil }
		let decryptedContent = try AES.GCM.open(sealedBox, using: symmetricKeyForDecrypt)
		return [UInt8](decryptedContent)
	}
	var transcript: SessionTranscript { SessionTranscript(devEngRawData: deviceEngagementRawData, eReaderRawData: eReaderKeyRawData, handOver: handOver) }
	
	/// SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]
	public var sessionTranscriptBytes: [UInt8] { transcript.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions()) }
	
	func getInfo(isEncrypt: Bool) -> String { isEncrypt ? (sessionRole == .mdoc ? "SKDevice" : "SKReader") : (sessionRole == .mdoc ? "SKReader" : "SKDevice") }
	
	/// Session keys are derived using ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman) as defined in BSI TR-03111
	func makeKeyAgreementAndDeriveSessionKey(isEncrypt: Bool) throws -> SymmetricKey?  {
		guard let sharedKey = sessionKeys.makeEckaDHAgreement() else { logger.error("Error in ECKA session key agreement"); return nil} //.x963Representation)
		let symmetricKey = try Self.HMACKeyDerivationFunction(sharedSecret: sharedKey, salt: sessionTranscriptBytes, info: getInfo(isEncrypt: isEncrypt).data(using: .utf8)!)
		return symmetricKey
	}

	
}

