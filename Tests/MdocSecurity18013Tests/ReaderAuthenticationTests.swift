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
import SwiftCBOR
import Testing
import MdocDataModel18013
@testable import MdocSecurity18013

extension MdocSecurity18013Tests {
    private struct ReaderTrustValidator: CertificateTrustValidator {
        var docType: String? = nil
        let trusted: Bool
        var mustNotBeCalled = false
        func createCertTrustPath(chain: [Data]) async -> [Data]? { trusted ? chain : nil }
        func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) {
            #expect(!mustNotBeCalled, "Invalid authentication must not reach trust evaluation")
            return (trusted, trusted ? nil : "Untrusted reader")
        }
    }

    @Test("Reader signature success returns certificate trust", arguments: [true, false])
    func readerAuthenticationTrustResult(_ trusted: Bool) async throws {
        let (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        let request = try DeviceRequest(data: AnnexdTestData.request_d411.bytes)
        #expect(!request.docRequests.isEmpty)
        for document in request.docRequests {
            let auth = try #require(document.readerAuthRawCBOR)
            let items = try #require(document.itemsRequestRawData)
            let result = try await MdocReaderAuthentication(transcript: session.sessionTranscript)
                .validateReaderAuth(readerAuthCBOR: auth, readerAuthX5c: document.readerCertificates,
                                    itemsRequestRawData: items, trustValidator: ReaderTrustValidator(trusted: trusted))
            #expect(result.0 == trusted)
            #expect(result.1 == (trusted ? nil : "Untrusted reader"))
        }
    }

    @Test("Reader authentication errors are distinct from trust failures", arguments: [
        "items", "transcript", "signature", "shortSignature", "emptyChain", "invalidCertificate",
        "invalidIntermediate", "structure", "header", "unprotectedHeader", "embeddedPayload",
        "missingAlgorithm", "positiveAlgorithm", "unsupportedAlgorithm"
    ])
    func readerAuthenticationFailure(_ mutation: String) async throws {
        typealias Failure = MdocReaderAuthentication.ReaderAuthenticationError
        let (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        let request = try DeviceRequest(data: AnnexdTestData.request_d411.bytes)
        let document = try #require(request.docRequests.first)
        var auth = try #require(document.readerAuthRawCBOR)
        var items = try #require(document.itemsRequestRawData)
        var chain = document.readerCertificates
        var transcript = session.sessionTranscript
        guard case var .array(fields) = auth else { Issue.record("Invalid fixture"); return }
        var expected = Failure.invalidSignature
        switch mutation {
        case "items": items[0] ^= 1
        case "transcript": transcript = SessionTranscript(handOver: .null)
        case "signature":
            guard case var .byteString(signature) = fields[3] else { Issue.record("Invalid fixture"); return }
            signature[0] ^= 1
            fields[3] = .byteString(signature)
        case "shortSignature": fields[3] = .byteString([0])
        case "emptyChain": chain = []; expected = .invalidCertificate
        case "invalidCertificate": chain = [Data([0xff])]; expected = .invalidCertificate
        case "invalidIntermediate": chain.append(Data([0xff])); expected = .invalidCertificate
        case "structure": fields = []; expected = .invalidStructure
        case "header": fields[0] = .byteString([0xff]); expected = .invalidStructure
        case "unprotectedHeader": fields[1] = .null; expected = .invalidStructure
        case "embeddedPayload": fields[2] = .byteString(items); expected = .invalidStructure
        case "missingAlgorithm": fields[0] = .byteString(CBOR.map([:]).encode()); expected = .unsupportedAlgorithm
        case "positiveAlgorithm":
            fields[0] = .byteString(CBOR.map([.unsignedInt(1): .unsignedInt(6)]).encode())
            expected = .unsupportedAlgorithm
        case "unsupportedAlgorithm":
            fields[0] = .byteString(CBOR.map([.unsignedInt(1): .negativeInt(999)]).encode())
            expected = .unsupportedAlgorithm
        default: Issue.record("Unknown mutation"); return
        }
        auth = .array(fields)
        do {
            _ = try await MdocReaderAuthentication(transcript: transcript).validateReaderAuth(
                readerAuthCBOR: auth, readerAuthX5c: chain, itemsRequestRawData: items,
                trustValidator: ReaderTrustValidator(trusted: true, mustNotBeCalled: true))
            Issue.record("Authentication failure was returned as a trust result")
        } catch let error as Failure {
            #expect(error == expected)
        }
    }
}
