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
import Testing
import SwiftCBOR

@testable import MdocDataModel18013
@testable import MdocSecurity18013

@Suite("MdocSecurity18013 Tests")
struct MdocSecurity18013Tests {

    @Test("Decode session transcript from annex D.5.1")
    func decodeSessionTranscriptAnnexD51() throws {
        let d = try #require(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionTranscriptData)))
        guard case let .tagged(_, v) = d, case let .byteString(bs) = v, let st = try CBOR.decode(bs) else {
            Issue.record("Not a tagged cbor"); return }
        _ = try SessionTranscript(cbor: st)
    }

    @Test("Decode session establishment from annex D.5.1")
    func decodeSessionEstablishmentAnnexD51() throws {
        let d = try #require(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionEstablishData)))
        _ = try SessionEstablishment(cbor: d)
    }

    @Test("Decode session data from annex D.5.1")
    func decodeSessionDataAnnexD51() throws {
        let d = try #require(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionData)))
        let sd = try SessionData(cbor: d)
        #expect(sd.data != nil)
        #expect(sd.status == nil)
    }

    @Test("Decode session termination from annex D.5.1")
    func decodeSessionTerminationAnnexD51() throws {
        let d = try #require(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionTermination)))
        let sd = try SessionData(cbor: d)
        #expect(sd.data == nil)
        #expect(sd.status != nil)
    }

    func makeSessionEncryptionFromAnnexData() throws -> (SessionEstablishment,SessionEncryption)? {
        let d = try #require(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionTranscriptData)))
		guard case let .tagged(t, v) = d, t == .encodedCBORDataItem, case let .byteString(bs) = v, let st = try CBOR.decode(bs) else {
             Issue.record("Not a tagged cbor"); return nil }
        let transcript = try SessionTranscript(cbor: st)
        let dse = try #require(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionEstablishData)))
        let se: SessionEstablishment = try SessionEstablishment(cbor: dse)
        var de = try DeviceEngagement(data: transcript.devEngRawData!)
        de.privateKey = Self.AnnexdTestData.d51_ephDeviceKey
        var sessionEncr = try #require(SessionEncryption(se: se, de: de, handOver: transcript.handOver))
		sessionEncr.deviceEngagementRawData = try #require(transcript.devEngRawData) // cbor encoding differs between implemenentations, for mDL with our own implementation they will be identical
        return (se, sessionEncr)
    }

      @Test("Decrypt session establishment from annex D.5.1")
      func decryptSessionEstablishmentAnnexD51() async throws {
        var (se,sessionEncr) = try #require(makeSessionEncryptionFromAnnexData())
 		#expect(Self.AnnexdTestData.d51_sessionTranscriptData == Data(sessionEncr.sessionTranscriptBytes))
        let data = try await sessionEncr.decrypt(se.data)
        let cbor = try #require(try CBOR.decode(data))
        print("Decrypted request:\n", cbor)
    }

    @Test("Compute DeviceAuthenticationBytes and MacStructure from annex D.5.3")
    func computeDeviceAuthenticationBytesAndMacStructureAnnexD53() async throws {
        let (_,sessionEncr) = try #require(makeSessionEncryptionFromAnnexData())
        var authKeys = CoseKeyExchange(publicKey: Self.AnnexdTestData.d51_ephReaderKey.key, privateKey: Self.AnnexdTestData.d53_deviceKey)
        if authKeys.privateKey.privateKeyId == nil { try await authKeys.privateKey.makeKey(curve: CoseEcCurve.P256) }
        let mdocAuth = MdocAuthentication(sessionTranscript: sessionEncr.sessionTranscript, authKeys: authKeys)
        let da = DeviceAuthentication(sessionTranscript: mdocAuth.sessionTranscript, docType: "org.iso.18013.5.1.mDL", deviceNameSpacesRawData: [0xA0])
        #expect(Data(da.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions())) == AnnexdTestData.d53_deviceAuthDeviceAuthenticationBytes)
        let coseIn = Cose(type: .mac0, algorithm: Cose.MacAlgorithm.hmac256.rawValue, payloadData: AnnexdTestData.d53_deviceAuthDeviceAuthenticationBytes)
		let dataToSign = try #require(coseIn.signatureStruct)
        #expect(dataToSign == AnnexdTestData.d53_deviceAuthMacStructure)
    }

    @Test("Compute deviceAuth CBOR data")
    func computeDeviceAuthCBORData() async throws {
        let (_,sessionEncr) = try #require(makeSessionEncryptionFromAnnexData())
        var authKeys = CoseKeyExchange(publicKey: Self.AnnexdTestData.d51_ephReaderKey.key, privateKey: Self.AnnexdTestData.d53_deviceKey)
        if authKeys.privateKey.privateKeyId == nil { try await authKeys.privateKey.makeKey(curve: CoseEcCurve.P256) }
        let mdocAuth = MdocAuthentication(sessionTranscript: sessionEncr.sessionTranscript, authKeys: authKeys)
		let bUseDeviceSign = UserDefaults.standard.bool(forKey: "PreferDeviceSignature")
        let dAuthO = try await mdocAuth.getDeviceAuthForTransfer(docType: "org.iso.18013.5.1.mDL", deviceNameSpacesRawData: [0xA0],
            dauthMethod: bUseDeviceSign ? .deviceSignature : .deviceMac, unlockData: nil)
		let deviceAuth = try #require(dAuthO)
        let ourDeviceAuthCBORbytes = deviceAuth.encode(options: CBOROptions())
        #expect(Data(ourDeviceAuthCBORbytes) == AnnexdTestData.d53_deviceAuthCBORdata)
    }

	@Test("Validate readerAuth CBOR data")
	func validateReaderAuthCBORData() throws {
		let (_,sessionEncr) = try #require(makeSessionEncryptionFromAnnexData())
		let dr = try DeviceRequest(data: AnnexdTestData.request_d411.bytes)
		for docR in dr.docRequests {
			let mdocAuth = MdocReaderAuthentication(transcript: sessionEncr.sessionTranscript)
			guard let readerAuthRawCBOR = docR.readerAuthRawCBOR else { continue }
			let (b, message) = try mdocAuth.validateReaderAuth(readerAuthCBOR: readerAuthRawCBOR, readerAuthX5c: docR.readerCertificates, itemsRequestRawData: docR.itemsRequestRawData!)
			#expect(!b, "Current date not in validity period of Certificate")
            print(message ?? "")
		}
	}
}
