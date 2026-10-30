/*
Copyright (c) 2026 European Commission

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
import CryptoKit
import MdocDataModel18013
import SwiftCBOR
import os

/// A session must be replaced after termination or counter exhaustion.
public enum SessionEncryptionError: Error, Equatable, Sendable {
    case counterExhausted
    case sessionTerminated
    case operationInProgress
    case encryptionFailed
}

/// Session encryption uses standard ephemeral key ECDH to establish session
/// keys for authenticated symmetric encryption.
/// The ``SessionEncryption`` struct implements session encryption (for the mDoc currently)
/// It is initialized from a) the session establishment data received from the
/// mdoc reader, b) the device engagement data generated from the mdoc and c)
/// the handover data.
/// Copies share message counters and terminal state. Operations in each direction
/// must be sequential; overlap is rejected. A cryptographic failure or cancellation
/// terminates the session. Only a fresh device engagement may create a new session.
///
/// ```swift
/// var se = SessionEncryption(se: sessionEstablishmentObject, de: deviceEngagementObject, handOver: handOverObject)
/// ```
public struct SessionEncryption: Sendable {
	public let sessionRole: SessionRole
    struct MessageCounters: Sendable {
        var encryption: UInt64 = 1
        var decryption: UInt64 = 1
        var encrypting = false
        var decrypting = false
        var terminated = false
    }
    // The lock's shared storage follows struct copies, including copies made by callers.
    let messageCounters = OSAllocatedUnfairLock(initialState: MessageCounters())
	var errorCode: UInt?
	static let IDENTIFIER0: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	static let IDENTIFIER1: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
	var encryptionIdentifier: [UInt8] { Self.IDENTIFIER1 }
	var decryptionIdentifier: [UInt8] { Self.IDENTIFIER0 }
	public var sessionKeys: CoseKeyExchange
	var deviceEngagementRawData: [UInt8]
	let eReaderKeyRawData: [UInt8]
	let handOver: CBOR
    let authenticationContext: ThreadSafeAuthContext

	/// Initialization of session encryption for the mdoc
	/// - Parameters:
	///   - se: session establishment data from the mdoc reader
	///   - de: device engagement created by the mdoc
	///   - handOver: handover object according to the transfer protocol
	public init?(se: SessionEstablishment, de: DeviceEngagement, handOver: CBOR, authenticationContext: ThreadSafeAuthContext) {
		sessionRole = .mdoc
		deviceEngagementRawData = de.qrCoded ?? de.encode(options: CBOROptions())
		guard let devicePrivateKey = de.privateKey else {
			logger.error("Device engagement for mdoc must have the private key")
			return nil
		}
		guard let readerKeyRawData = se.eReaderKeyRawData else {
			logger.error("Reader key data not available")
			return nil
		}
		self.eReaderKeyRawData = readerKeyRawData
		guard let readerPublicKey = se.eReaderKey else {
			logger.error("Could not decode ereader key")
			return nil
		}
		sessionKeys = CoseKeyExchange(publicKey: readerPublicKey, privateKey: devicePrivateKey)
		self.handOver = handOver
        self.authenticationContext = authenticationContext
	}

	/// Make nonce function to initialize the encryption or decryption
	///
	/// - Parameters:
	///   - counter: The message counter value shall be a 4-byte big-endian
	///     unsigned integer. For the first encryption with a session key, the
	///     message counter shall be set to 1. Before each following encryption
	///     with the same key, the message counter value shall be increased by 1
	///   - isEncrypt: is for encrypt?
	/// - Returns: The IV (Initialization Vector) used for the encryption.
	func makeNonce(_ counter: UInt32, isEncrypt: Bool) throws -> AES.GCM.Nonce {
		var dataNonce = Data()
		let identifier = isEncrypt ? encryptionIdentifier : decryptionIdentifier
		dataNonce.append(Data(identifier))
		dataNonce.append(Data(counter.byteArrayBigEndian))
		let nonce = try AES.GCM.Nonce(data: dataNonce)
		return nonce
	}

	/// computation of HKDF symmetric key
	static func HMACKeyDerivationFunction(sharedSecret: SharedSecret, salt: [UInt8], info: Data) throws -> SymmetricKey {
		let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
			using: SHA256.self,
			salt: salt,
			sharedInfo: info,
			outputByteCount: 32
		)
		return symmetricKey
	}

	/// encrypt data using current nonce as described in 9.1.1.5 Cryptographic operations
	mutating public func encrypt(_ data: [UInt8]) async throws -> [UInt8]? {
        let counter = try beginOperation(isEncrypt: true)
        defer { endOperation(isEncrypt: true) }
        do {
            let nonce = try makeNonce(counter, isEncrypt: true)
            let key = try await makeKeyAgreementAndDeriveSessionKey(isEncrypt: true)
            try Task.checkCancellation()
            try checkActive()
            let box = try AES.GCM.seal(data, using: key, nonce: nonce)
            guard let content = box.combined else { throw SessionEncryptionError.encryptionFailed }
            return Array(content.dropFirst(12))
        } catch {
            invalidate()
            throw error
        }
	}

	/// decryptes cipher data using the symmetric key
	mutating public func decrypt(_ ciphertext: [UInt8]) async throws -> [UInt8] {
        let counter = try beginOperation(isEncrypt: false)
        defer { endOperation(isEncrypt: false) }
        do {
            let nonce = try makeNonce(counter, isEncrypt: false)
            let box = try AES.GCM.SealedBox(combined: nonce + ciphertext)
            let key = try await makeKeyAgreementAndDeriveSessionKey(isEncrypt: false)
            try Task.checkCancellation()
            try checkActive()
            return Array(try AES.GCM.open(box, using: key))
        } catch {
            invalidate()
            throw error
        }
	}

    /// Terminates this session and all its copies. A fresh engagement is required to resume.
    public func invalidate() {
        messageCounters.withLock { $0.terminated = true }
    }

    private func checkActive() throws {
        try messageCounters.withLock { state in
            if state.terminated { throw SessionEncryptionError.sessionTerminated }
        }
    }

    private func beginOperation(isEncrypt: Bool) throws -> UInt32 {
        try messageCounters.withLock { state in
            guard !state.terminated else { throw SessionEncryptionError.sessionTerminated }
            // Never hold a lock across await. Reject overlapping operations in one direction
            // so callers cannot accidentally deliver ciphertext in the wrong counter order.
            guard !(isEncrypt ? state.encrypting : state.decrypting) else { throw SessionEncryptionError.operationInProgress }
            let counter = isEncrypt ? state.encryption : state.decryption
            guard counter <= UInt64(UInt32.max) else {
                state.terminated = true
                throw SessionEncryptionError.counterExhausted
            }
            if isEncrypt {
                state.encryption += 1
                state.encrypting = true
            } else {
                state.decryption += 1
                state.decrypting = true
            }
            return UInt32(counter)
        }
    }

    private func endOperation(isEncrypt: Bool) {
        messageCounters.withLock { state in
            if isEncrypt { state.encrypting = false } else { state.decrypting = false }
        }
    }
	public var sessionTranscript: SessionTranscript {
		SessionTranscript(
			devEngRawData: deviceEngagementRawData,
			eReaderRawData: eReaderKeyRawData,
			handOver: handOver
		)
	}

	/// SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]
	public var sessionTranscriptBytes: [UInt8] {
		let trCbor = sessionTranscript.taggedEncoded
		return trCbor.encode(options: CBOROptions())
	}

	func getInfo(isEncrypt: Bool) -> String {
		if isEncrypt {
			return "SKDevice"
		}
		return "SKReader"
	}

	/// Session keys are derived using ECKA-DH (Elliptic Curve Key Agreement
	/// Algorithm – Diffie-Hellman) as defined in BSI TR-03111
	mutating func makeKeyAgreementAndDeriveSessionKey(isEncrypt: Bool) async throws -> SymmetricKey  {
        let sharedKey = try await sessionKeys.makeEckaDHAgreement(authenticationContext: authenticationContext)
		let keyInfo = getInfo(isEncrypt: isEncrypt).data(using: .utf8)!
		let symmetricKey = try Self.HMACKeyDerivationFunction(
			sharedSecret: sharedKey,
			salt: sessionTranscriptBytes,
			info: keyInfo
		)
		return symmetricKey
	}


}

