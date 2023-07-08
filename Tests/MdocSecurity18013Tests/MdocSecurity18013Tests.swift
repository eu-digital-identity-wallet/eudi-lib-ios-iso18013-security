import XCTest
import SwiftCBOR
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
}
