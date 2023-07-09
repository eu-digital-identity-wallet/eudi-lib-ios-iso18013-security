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

    func test_decrypt_session_establishment_annex_d51() throws {
        let d = try XCTUnwrap(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionTranscriptData)))
		guard case let .tagged(t, v) = d, t == .encodedCBORDataItem, case let .byteString(bs) = v, let st = try CBOR.decode(bs) else {
             XCTFail("Not a tagged cbor"); return }
        let transcript = try XCTUnwrap(SessionTranscript(cbor: st))
        let dse = try XCTUnwrap(try CBOR.decode([UInt8](Self.AnnexdTestData.d51_sessionEstablishData)))
        let se: SessionEstablishment = try XCTUnwrap(SessionEstablishment(cbor: dse))
        var de = try XCTUnwrap(DeviceEngagement(data: transcript.devEngRawData))
        de.setD(d: Self.AnnexdTestData.ephDeviceKey.d)
        var sessionEncr = try XCTUnwrap(SessionEncryption(deviceKey: AnnexdTestData.deviceKey, se: se, de: de, handOver: transcript.handOver))
		sessionEncr.deviceEngagementRawData = transcript.devEngRawData // cbor encoding differs between implemenentations
		XCTAssertEqual(Self.AnnexdTestData.d51_sessionTranscriptData, Data(sessionEncr.sessionTranscriptBytes))
        let data = try XCTUnwrap(try sessionEncr.decrypt(se.data))
        let cbor = try XCTUnwrap(try CBOR.decode(data))
        print("Decrypted request:\n", cbor)
    }
}
