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

#if canImport(EudiEtsi1196x2)
import CryptoKit
import Foundation
import SwiftASN1
import X509
import Testing
import EudiEtsi1196x2

@testable import MdocSecurity18013

/// Tests for the caller-supplied `EtsiTrustSource.loadLoTE`.
/// No network access: every LoTE is served by the injected loader.
@Suite("EtsiTrustSource custom LoTE loader Tests")
struct EtsiTrustSourceLoadLoTETests {
    let mdlUrl = "https://example.test/mdl.jwt"
    let root: Data
    let leaf: Data

    init() throws {
        root = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-root", withExtension: "der")))
        leaf = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-leaf", withExtension: "der")))
    }

    @Test("Chain is validated against anchors from the injected loader, served from cache on repeat")
    func injectedLoaderProvidesAnchors() async {
        let loader = RecordingLoadLoTE(jwt: Self.mdlLoTEJwt(certificate: root))
        let manager = makeManager(loader: loader)

        let (trusted, reason) = await manager.validateCertTrustPath(chain: [leaf])
        let (trustedAgain, _) = await manager.validateCertTrustPath(chain: [leaf])

        #expect(trusted, "reason: \(reason ?? "nil")")
        #expect(trustedAgain)
        #expect(loader.requestedUris == [mdlUrl])
    }

    @Test("The default verifier authenticates the signer of lists returned by the custom loader",
          arguments: ["CA", "leaf", "unrelated CA", "empty", "altered signature", "expired leaf"])
    func defaultVerifier(anchor: String) async throws {
        let signingKey = P256.Signing.PrivateKey()
        let caKey = P256.Signing.PrivateKey()
        let ca = try X509.DistinguishedName { CommonName("LoTE test CA") }
        let signer = try X509.DistinguishedName { CommonName("LoTE test signer") }
        let caCertificate = try makeCertificate(subject: ca, issuer: ca, key: caKey, issuerKey: caKey, isCA: true)
        let signerCertificate = try makeCertificate(
            subject: signer, issuer: ca, key: signingKey, issuerKey: caKey, expired: anchor == "expired leaf"
        )
        let header = try JSONSerialization.data(withJSONObject: [
            "alg": "ES256", "x5c": [signerCertificate.base64EncodedString()]
        ])
        let payload = Self.mdlLoTEPayload(certificate: root)
        let input = "\(header.base64URLEncoded).\(payload.base64URLEncoded)"
        var signature = try signingKey.signature(for: Data(input.utf8)).rawRepresentation
        if anchor == "altered signature" { signature[0] ^= 1 }
        let loader = RecordingLoadLoTE(jwt: "\(input).\(signature.base64URLEncoded)")
        let anchors: [Data]
        switch anchor {
        case "leaf", "expired leaf": anchors = [signerCertificate]
        case "unrelated CA": anchors = [root]
        case "empty": anchors = []
        default: anchors = [caCertificate]
        }
        let config = makeSource(loader: loader, signerTrustAnchors: anchors, verifier: nil)
        let manager = EtsiTrustManager(
            source: TrustSource.etsi(config).withContextTypeMappings(nil),
            defaultVerificationContext: EtsiContextType.mdl.verificationContext
        )

        let (trusted, reason) = await manager.validateCertTrustPath(chain: [leaf])
        #expect(trusted == (anchor == "CA" || anchor == "leaf"), "reason: \(reason ?? "nil")")
        #expect(loader.requestedUris == [mdlUrl])
    }

    private func makeCertificate(
        subject: X509.DistinguishedName, issuer: X509.DistinguishedName, key: P256.Signing.PrivateKey,
        issuerKey: P256.Signing.PrivateKey, isCA: Bool = false, expired: Bool = false
    ) throws -> Data {
        let now = Date()
        let extensions = try Certificate.Extensions {
            Critical(isCA ? BasicConstraints.isCertificateAuthority(maxPathLength: nil) : .notCertificateAuthority)
            Critical(KeyUsage(digitalSignature: !isCA, keyCertSign: isCA))
        }
        let certificate = try Certificate(
            version: .v3, serialNumber: isCA ? 1 : 2, publicKey: .init(key.publicKey),
            notValidBefore: now.addingTimeInterval(-3600), notValidAfter: now.addingTimeInterval(expired ? -60 : 3600),
            issuer: issuer, subject: subject, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions, issuerPrivateKey: .init(issuerKey)
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }

    @Test("A list the loader cannot provide yields an untrusted result without network access")
    func missingListIsNotTrusted() async {
        let loader = RecordingLoadLoTE(jwt: nil)
        let manager = makeManager(loader: loader)

        let (trusted, _) = await manager.validateCertTrustPath(chain: [leaf])

        #expect(trusted == false)
        #expect(loader.requestedUris == [mdlUrl])
    }

    @Test("withContextTypeMappings keeps the custom loader")
    func contextTypeMappingsKeepLoader() {
        let loader = RecordingLoadLoTE(jwt: nil)
        let source = TrustSource.etsi(makeSource(loader: loader)).withContextTypeMappings(.default)

        guard case .etsi(let etsi) = source else {
            Issue.record("Expected an ETSI trust source")
            return
        }
        #expect(etsi.loadLoTE as AnyObject === loader)
    }

    private func makeSource(
        loader: RecordingLoadLoTE, signerTrustAnchors: [Data] = [],
        verifier: (any VerifyJwtSignature)? = AcceptAllJwtSignature()
    ) -> EtsiTrustSource {
        let lists = SupportedLists<NSString>(
            pidProviders: nil,
            walletProviders: nil,
            wrpacProviders: nil,
            wrprcProviders: nil,
            pubEaaProviders: nil,
            qeaProviders: nil,
            eaaProviders: [EudiwIosTrust.shared.mdlUseCase: mdlUrl as NSString]
        )
        return EtsiTrustSource(
            loteLocations: lists,
            loteSignerTrustAnchors: signerTrustAnchors,
            customJwtSignatureVerifier: verifier,
            loadLoTE: loader,
            revocationPolicy: .disabled
        )
    }

    private func makeManager(loader: RecordingLoadLoTE) -> EtsiTrustManager {
        EtsiTrustManager(
            source: .etsi(makeSource(loader: loader)),
            defaultVerificationContext: EtsiContextType.mdl.verificationContext
        )
    }

    /// An unsigned mDL providers LoTE whose single issuance service lists `certificate`.
    private static func mdlLoTEJwt(certificate: Data) -> String {
        let header = Data(#"{"alg":"none"}"#.utf8)
        let payload = mdlLoTEPayload(certificate: certificate)
        return "\(header.base64URLEncoded).\(payload.base64URLEncoded).signature"
    }

    private static func mdlLoTEPayload(certificate: Data) -> Data {
        let now = Date()
        let formatter = ISO8601DateFormatter()
        let lote: [String: Any] = [
            "LoTE": [
                "ListAndSchemeInformation": [
                    "LoTEVersionIdentifier": 1,
                    "LoTESequenceNumber": 1,
                    "SchemeOperatorName": [["lang": "en", "value": "Test Scheme Operator"]],
                    "SchemeTerritory": "EU",
                    "ListIssueDateTime": formatter.string(from: now),
                    "NextUpdate": formatter.string(from: now.addingTimeInterval(30 * 24 * 3600)),
                ],
                "TrustedEntitiesList": [[
                    "TrustedEntityInformation": [
                        "TEName": [["lang": "en", "value": "Test mDL Provider"]],
                        "TEAddress": [
                            "TEPostalAddress": [["lang": "en", "StreetAddress": "1 Test Street", "Country": "EU"]],
                            "TEElectronicAddress": [["lang": "en", "uriValue": "mailto:test@example.test"]],
                        ],
                        "TEInformationURI": [["lang": "en", "uriValue": "https://example.test/info"]],
                    ],
                    "TrustedEntityServices": [[
                        "ServiceInformation": [
                            "ServiceName": [["lang": "en", "value": "Test mDL Issuance"]],
                            "ServiceDigitalIdentity": ["X509Certificates": [["val": certificate.base64EncodedString()]]],
                            "ServiceTypeIdentifier": "http://trust.ec.europa.eu/lists/mDL/SvcType/Issuance",
                        ],
                    ]],
                ]],
            ],
        ]
        return (try? JSONSerialization.data(withJSONObject: lote)) ?? Data()
    }
}

/// Serves a fixed LoTE (or reports it as not found) and records every requested URI.
private final class RecordingLoadLoTE: IosLoadLoTE, @unchecked Sendable {
    private let jwt: String?
    private let lock = NSLock()
    private var uris: [String] = []

    var requestedUris: [String] { lock.withLock { uris } }

    init(jwt: String?) {
        self.jwt = jwt
    }

    func loadLoTE(uri: String) async throws -> any LoadLoTEOutcome {
        lock.withLock { uris.append(uri) }
        guard let jwt else { return LoadLoTEOutcomeNotFound(cause: nil) }
        return LoadLoTEOutcomeLoaded<NSString>(content: jwt as NSString)
    }
}

/// Test-only verifier: the LoTE fixture is unsigned.
private final class AcceptAllJwtSignature: VerifyJwtSignature, @unchecked Sendable {
    func invoke(jwt: String) async throws -> any VerifyJwtSignatureOutcome {
        VerifyJwtSignatureOutcomeVerified(jwt: jwt)
    }
}

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
#endif
