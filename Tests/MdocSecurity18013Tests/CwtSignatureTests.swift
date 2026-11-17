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

#if canImport(JSONWebSignature)
import CryptoKit
import Foundation
import JSONWebSignature
import SwiftASN1
import SwiftCBOR
import Testing
import X509

@testable import MdocDataModel18013
@testable import MdocSecurity18013

@Suite("CWT signature verification")
struct CwtSignatureTests {
    private struct TrustValidator: CertificateTrustValidator {
        var docType: String? = nil
        let trusted: Bool
        var mustNotBeCalled = false
        func createCertTrustPath(chain: [Data]) async -> [Data]? { trusted ? chain : nil }
        func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) {
            #expect(!mustNotBeCalled, "Chain validation must not run before authenticating the signature")
            return (trusted, trusted ? nil : "Untrusted issuer")
        }
    }

    @Test("Valid signatures are accepted for supported algorithms", arguments: [
        Cose.VerifyAlgorithm.es256, .esp256, .es384, .es512
    ])
    func acceptsValidSignature(_ algorithm: Cose.VerifyAlgorithm) async throws {
        let token = try makeToken(algorithm: algorithm)
        let (trusted, reason) = try await x5cVerifyJwtOrCwt.validateTrust(token, trustValidator: TrustValidator(trusted: true))
        #expect(trusted)
        #expect(reason == nil)
    }

    @Test("Verification preserves the original protected-header encoding")
    func preservesProtectedBytes() async throws {
        // Valid, non-preferred CBOR encoding of {1: -7}; re-encoding changes the signed bytes.
        let token = try makeToken(headerBytes: [0xa1, 0x18, 0x01, 0x38, 0x06])
        #expect(try await x5cVerifyJwtOrCwt.validateTrust(token, trustValidator: TrustValidator(trusted: true)).0)
    }

    @Test("Valid signature does not bypass issuer trust")
    func rejectsUntrustedChain() async throws {
        let token = try makeToken()
        let (trusted, reason) = try await x5cVerifyJwtOrCwt.validateTrust(token, trustValidator: TrustValidator(trusted: false))
        #expect(!trusted)
        #expect(reason == "Untrusted issuer")
    }

    @Test("Invalid CWTs throw before chain validation", arguments: [
        "payload", "protectedHeader", "signature", "emptySignature", "wrongKey", "wrongCurve",
        "unsupportedAlgorithm", "positiveAlgorithm", "missingAlgorithm", "detachedPayload", "textPayload",
        "invalidCertificate"
    ])
    func rejectsInvalidToken(_ mutation: String) async throws {
        let token = try makeToken(mutation: mutation)
        do {
            _ = try await x5cVerifyJwtOrCwt.validateTrust(
                token, trustValidator: TrustValidator(trusted: true, mustNotBeCalled: true)
            )
            Issue.record("Accepted invalid CWT: \(mutation)")
        } catch {
            // A thrown error is essential: consumers may downgrade a false trust result to a warning.
        }
    }

    @Test("JWT signatures are still checked before trust", arguments: [false, true])
    func jwtRegression(_ tampered: Bool) async throws {
        let key = P256.Signing.PrivateKey()
        let certificate = try certificateBytes(key: .init(key), publicKey: .init(key.publicKey), algorithm: .ecdsaWithSHA256)
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "x5c": [Data(certificate).base64EncodedString()]])
        let payload = Data("{\"sub\":\"test\"}".utf8)
        func base64URL(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let signedPart = base64URL(header) + "." + base64URL(payload)
        let signature = try key.signature(for: Data(signedPart.utf8)).rawRepresentation
        let tokenString = base64URL(header) + "." + base64URL(tampered ? Data("{}".utf8) : payload) + "." + base64URL(signature)
        let token = try x5cVerifyJwtOrCwt.parse(attestData: Data(tokenString.utf8), format: .jwt)
        do {
            let result = try await x5cVerifyJwtOrCwt.validateTrust(
                token, trustValidator: TrustValidator(trusted: true, mustNotBeCalled: tampered)
            )
            #expect(!tampered)
            #expect(result.0)
        } catch {
            #expect(tampered, "Valid JWT rejected: \(error)")
        }
    }

    private func certificateBytes(key: Certificate.PrivateKey, publicKey: Certificate.PublicKey,
                                  algorithm: Certificate.SignatureAlgorithm) throws -> [UInt8] {
        let name = try DistinguishedName { CommonName("CWT signature test") }
        let certificate = try Certificate(
            version: .v3, serialNumber: 1, publicKey: publicKey,
            notValidBefore: Date().addingTimeInterval(-3600), notValidAfter: Date().addingTimeInterval(3600),
            issuer: name, subject: name, signatureAlgorithm: algorithm,
            extensions: Certificate.Extensions {}, issuerPrivateKey: key
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }

    private func makeToken(algorithm: Cose.VerifyAlgorithm = .es256, headerBytes: [UInt8]? = nil,
                           mutation: String? = nil) throws -> AttestToken {
        let certificate: [UInt8]
        let sign: (Data) throws -> Data
        switch algorithm {
        case .es256, .esp256:
            let key = P256.Signing.PrivateKey()
            certificate = try certificateBytes(key: .init(key), publicKey: .init(key.publicKey), algorithm: .ecdsaWithSHA256)
            sign = { try key.signature(for: $0).rawRepresentation }
        case .es384:
            let key = P384.Signing.PrivateKey()
            certificate = try certificateBytes(key: .init(key), publicKey: .init(key.publicKey), algorithm: .ecdsaWithSHA384)
            sign = { try key.signature(for: $0).rawRepresentation }
        case .es512:
            let key = P521.Signing.PrivateKey()
            certificate = try certificateBytes(key: .init(key), publicKey: .init(key.publicKey), algorithm: .ecdsaWithSHA512)
            sign = { try key.signature(for: $0).rawRepresentation }
        }
        var headers: CBOR = .map([.unsignedInt(1): .negativeInt(algorithm.rawValue)])
        switch mutation {
        case "unsupportedAlgorithm": headers = .map([.unsignedInt(1): .negativeInt(999)])
        case "positiveAlgorithm": headers = .map([.unsignedInt(1): .unsignedInt(algorithm.rawValue)])
        case "missingAlgorithm": headers = .map([:])
        case "wrongCurve": headers = .map([.unsignedInt(1): .negativeInt(Cose.VerifyAlgorithm.es384.rawValue)])
        default: break
        }
        var protected: CBOR = .byteString(headerBytes ?? headers.encode())
        var payload: CBOR = .byteString(CBOR.map([.unsignedInt(2): .utf8String("test")]).encode())
        let signingData = Data(CBOR.array([.utf8String("Signature1"), protected, .byteString([]), payload]).encode())
        var signature = try sign(signingData)
        switch mutation {
        case "payload": payload = .byteString([0xa0])
        case "protectedHeader": protected = .byteString(CBOR.map([.unsignedInt(1): .negativeInt(algorithm.rawValue), .unsignedInt(16): .utf8String("changed")]).encode())
        case "signature": signature[0] ^= 1
        case "emptySignature": signature = Data()
        case "wrongKey": signature = try P256.Signing.PrivateKey().signature(for: signingData).rawRepresentation
        case "detachedPayload": payload = .null
        case "textPayload": payload = .utf8String("test")
        default: break
        }
        let chain = mutation == "invalidCertificate" ? [0xff] : certificate
        let encoded = CBOR.array([protected, .map([.unsignedInt(33): .byteString(chain)]), payload, .byteString(Array(signature))]).encode()
        return try x5cVerifyJwtOrCwt.parse(attestData: Data(encoded), format: .cwt)
    }
}
#endif
