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

import CryptoKit
import Foundation
import SwiftASN1
import SwiftCBOR
import Testing
import X509

@testable import MdocDataModel18013
@testable import MdocSecurity18013

@Suite("MSO trust warnings")
struct MsoTrustWarningTests {
    private struct TrustValidator: CertificateTrustValidator {
        var docType: String? = nil
        let trusted: Bool
        func createCertTrustPath(chain: [Data]) async -> [Data]? { trusted ? chain : nil }
        func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) {
            (trusted, trusted ? nil : "Unrecognized test issuer")
        }
    }

    @Test("Warning policy returns the trust failure and preserves prior warnings")
    func returnsTrustWarning() async throws {
        let issuer = try makeIssuer()
        var keys = [issuer.issuerAuth.mso.deviceKeyInfo.deviceKey]
        var warnings: [MsoValidationError] = [.issuerTrustFailed("Earlier warning")]
        try await issuer.validate(docType: "test", trustValidator: TrustValidator(trusted: false),
                                  trustPolicy: .warning, publicCoseKeys: &keys, warnings: &warnings)
        #expect(warnings.count == 2)
        #expect(warnings.first?.errorDescription?.contains("Earlier warning") == true)
        guard case .issuerTrustFailed(let reason) = warnings.last else {
            Issue.record("Expected an issuer-trust warning")
            return
        }
        #expect(reason == "Unrecognized test issuer")
        #expect(keys.isEmpty)
    }

    @Test("Enforce policy throws the trust failure")
    func enforcesTrust() async throws {
        let issuer = try makeIssuer()
        var keys = [issuer.issuerAuth.mso.deviceKeyInfo.deviceKey]
        var warnings: [MsoValidationError] = []
        do {
            try await issuer.validate(docType: "test", trustValidator: TrustValidator(trusted: false),
                                      trustPolicy: .enforce, publicCoseKeys: &keys, warnings: &warnings)
            Issue.record("Untrusted issuer was accepted")
        } catch {
            guard case .issuerTrustFailed(let reason) = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(reason == "Unrecognized test issuer")
        }
        #expect(warnings.isEmpty)
    }

    @Test("Trusted issuers produce no warnings", arguments: [TrustPolicy.warning, .enforce])
    func trustedIssuer(_ policy: TrustPolicy) async throws {
        let issuer = try makeIssuer()
        var keys = [issuer.issuerAuth.mso.deviceKeyInfo.deviceKey]
        var warnings: [MsoValidationError] = []
        try await issuer.validate(docType: "test", trustValidator: TrustValidator(trusted: true),
                                  trustPolicy: policy, publicCoseKeys: &keys, warnings: &warnings)
        #expect(warnings.isEmpty)
    }

    @Test("Existing API remains non-blocking under warning policy")
    func existingAPI() async throws {
        let issuer = try makeIssuer()
        var keys = [issuer.issuerAuth.mso.deviceKeyInfo.deviceKey]
        try await issuer.validate(docType: "test", trustValidator: TrustValidator(trusted: false),
                                  trustPolicy: .warning, publicCoseKeys: &keys)
    }

    @Test("Warning policy does not suppress other failures",
          arguments: ["signature", "validity", "binding", "docType", "digestAlgorithm"])
    func otherFailuresRemainBlocking(_ failure: String) async throws {
        let issuer = try makeIssuer(failure: failure)
        var keys = failure == "binding" ? [] : [issuer.issuerAuth.mso.deviceKeyInfo.deviceKey]
        var warnings: [MsoValidationError] = []
        do {
            try await issuer.validate(docType: failure == "docType" ? "other" : "test",
                                      trustValidator: TrustValidator(trusted: false),
                                      trustPolicy: .warning, publicCoseKeys: &keys, warnings: &warnings)
            Issue.record("Accepted invalid \(failure)")
        } catch {
            switch (failure, error) {
            case ("signature", .signatureVerificationFailed), ("binding", .signatureVerificationFailed),
                 ("validity", .validityInfo), ("docType", .docTypeNotMatches),
                 ("digestAlgorithm", .unsupportedDigestAlgorithm): break
            default: Issue.record("Unexpected error for \(failure): \(error)")
            }
        }
        #expect(warnings.count == 1)
    }

    private func makeIssuer(failure: String? = nil) throws -> IssuerSigned {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName("MSO warning test") }
        let now = Date()
        let certificate = try Certificate(
            version: .v3, serialNumber: 1, publicKey: .init(key.publicKey),
            notValidBefore: now.addingTimeInterval(-7200), notValidAfter: now.addingTimeInterval(7200),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {}, issuerPrivateKey: .init(key)
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        let formatter = ISO8601DateFormatter()
        let mso = MobileSecurityObject(
            version: "1.0", digestAlgorithm: failure == "digestAlgorithm" ? "unsupported" : "SHA-256",
            valueDigests: ValueDigests(valueDigests: [:]),
            deviceKey: CoseKey(crv: .P256, x963Representation: key.publicKey.x963Representation),
            docType: "test",
            validityInfo: ValidityInfo(
                signed: formatter.string(from: now.addingTimeInterval(-3600)),
                validFrom: formatter.string(from: now.addingTimeInterval(-3600)),
                validUntil: formatter.string(from: now.addingTimeInterval(failure == "validity" ? -120 : 3600)),
                expectedUpdate: nil
            )
        )
        let payload = CBOR.tagged(.encodedCBORDataItem, .byteString(mso.toCBOR(options: CBOROptions()).encode())).encode()
        let cose = Cose(type: .sign1, algorithm: Cose.VerifyAlgorithm.es256.rawValue, payloadData: Data(payload))
        let signingData = try #require(cose.signatureStruct)
        let signer = failure == "signature" ? P256.Signing.PrivateKey() : key
        let signature = try signer.signature(for: signingData).rawRepresentation
        return IssuerSigned(issuerNameSpaces: nil, issuerAuth: IssuerAuth(
            mso: mso, msoRawData: payload, verifyAlgorithm: .es256, signature: signature,
            x5chain: [serializer.serializedBytes], statusList: nil
        ))
    }
}
