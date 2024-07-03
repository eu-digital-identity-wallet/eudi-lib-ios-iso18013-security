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

import XCTest
import SwiftCBOR

@testable import MdocDataModel18013
@testable import MdocSecurity18013

final class MdocSecurity18013Tests: XCTestCase {

    func test_decode_session_transcript_annex_d51() throws {
        let d = try XCTUnwrap(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionTranscriptData)))
        guard case let .tagged(_, v) = d, case let .byteString(bs) = v, let st = try CBOR.decode(bs) else {
             XCTFail("Not a tagged cbor"); return }
        let transcript = try XCTUnwrap(SessionTranscript(cbor: st))
        XCTAssertNotNil(transcript)
    }

    func test_decode_session_establishment_annex_d51() throws {
        let d = try XCTUnwrap(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionEstablishData)))
        let se: SessionEstablishment = try XCTUnwrap(SessionEstablishment(cbor: d))
        XCTAssertNotNil(se)
    }

    func test_decode_session_data_annex_d51() throws {
        let d = try XCTUnwrap(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionData)))
        let sd = try XCTUnwrap(SessionData(cbor: d))
        XCTAssertNotNil(sd.data)
        XCTAssertNil(sd.status)
    }

    func test_decode_session_termination_annex_d51() throws {
        let d = try XCTUnwrap(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionTermination)))
        let sd = try XCTUnwrap(SessionData(cbor: d))
        XCTAssertNil(sd.data)
        XCTAssertNotNil(sd.status)
    }

    func make_session_encryption_from_annex_data() throws -> (SessionEstablishment,SessionEncryption)? {
        let d = try XCTUnwrap(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionTranscriptData)))
		guard case let .tagged(t, v) = d, t == .encodedCBORDataItem, case let .byteString(bs) = v, let st = try CBOR.decode(bs) else {
             XCTFail("Not a tagged cbor"); return nil }
        let transcript = try XCTUnwrap(SessionTranscript(cbor: st))
        let dse = try XCTUnwrap(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionEstablishData)))
        let se: SessionEstablishment = try XCTUnwrap(SessionEstablishment(cbor: dse))
        var de = try XCTUnwrap(DeviceEngagement(data: transcript.devEngRawData!))
        de.setD(d: Self.AnnexdTestData.d51_ephDeviceKey.d)
        var sessionEncr = try XCTUnwrap(SessionEncryption(se: se, de: de, handOver: transcript.handOver))
		sessionEncr.deviceEngagementRawData = try XCTUnwrap(transcript.devEngRawData) // cbor encoding differs between implemenentations, for mDL with our own implementation they will be identical
        return (se, sessionEncr)
    }
     
      func test_decrypt_session_establishment_annex_d51() throws {
        var (se,sessionEncr) = try XCTUnwrap(make_session_encryption_from_annex_data())
 		XCTAssertEqual(Self.AnnexdTestData.d51_sessionTranscriptData, Data(sessionEncr.sessionTranscriptBytes))
        let data = try XCTUnwrap(try sessionEncr.decrypt(se.data))
        let cbor = try XCTUnwrap(try CBOR.decode(data))
        print("Decrypted request:\n", cbor)
    }

    func test_compute_DeviceAuthenticationBytes_and_MacStructure_annex_d53() throws {
        let (_,sessionEncr) = try XCTUnwrap(make_session_encryption_from_annex_data())
        let authKeys = CoseKeyExchange(publicKey: Self.AnnexdTestData.d51_ephReaderKey.key, privateKey: Self.AnnexdTestData.d53_deviceKey)
        let mdocAuth = MdocAuthentication(transcript: sessionEncr.transcript, authKeys: authKeys)
        let da = DeviceAuthentication(sessionTranscript: mdocAuth.transcript, docType: "org.iso.18013.5.1.mDL", deviceNameSpacesRawData: [0xA0])
        XCTAssertEqual(Data(da.toCBOR(options: CBOROptions()).taggedEncoded.encode(options: CBOROptions())), AnnexdTestData.d53_deviceAuthDeviceAuthenticationBytes)
        let coseIn = Cose(type: .mac0, algorithm: Cose.MacAlgorithm.hmac256.rawValue, payloadData: AnnexdTestData.d53_deviceAuthDeviceAuthenticationBytes)
		let dataToSign = try XCTUnwrap(coseIn.signatureStruct)
        XCTAssertEqual(dataToSign, AnnexdTestData.d53_deviceAuthMacStructure)
    }

    func test_compute_deviceAuth_CBOR_data() throws {
        let (_,sessionEncr) = try XCTUnwrap(make_session_encryption_from_annex_data())
        let authKeys = CoseKeyExchange(publicKey: Self.AnnexdTestData.d51_ephReaderKey.key, privateKey: Self.AnnexdTestData.d53_deviceKey)
        let mdocAuth = MdocAuthentication(transcript: sessionEncr.transcript, authKeys: authKeys)
		let bUseDeviceSign = UserDefaults.standard.bool(forKey: "PreferDeviceSignature")
		let deviceAuth = try XCTUnwrap(try mdocAuth.getDeviceAuthForTransfer(docType: "org.iso.18013.5.1.mDL", deviceNameSpacesRawData: [0xA0], 
            dauthMethod: bUseDeviceSign ? .deviceSignature : .deviceMac))
        let ourDeviceAuthCBORbytes = deviceAuth.encode(options: CBOROptions())
        XCTAssertEqual(Data(ourDeviceAuthCBORbytes), AnnexdTestData.d53_deviceAuthCBORdata)
    }

	func test_validate_readerAuth_CBOR_data() throws {
		let (_,sessionEncr) = try XCTUnwrap(make_session_encryption_from_annex_data())
		let dr = try XCTUnwrap(DeviceRequest(data: AnnexdTestData.request_d411.bytes))
		for docR in dr.docRequests {
			let mdocAuth = MdocReaderAuthentication(transcript: sessionEncr.transcript)
			guard let readerAuthRawCBOR = docR.readerAuthRawCBOR else { continue }
			let (b, message) = try mdocAuth.validateReaderAuth(readerAuthCBOR: readerAuthRawCBOR, readerAuthCertificate: docR.readerCertificate!, itemsRequestRawData: docR.itemsRequestRawData!)
			XCTAssertTrue(b, "Reader auth signature not validated")
            print(message ?? "")
		}
	}
}
