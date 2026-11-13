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
import Foundation
import Testing
import EudiEtsi1196x2

@testable import MdocSecurity18013

@Suite("PkixRevocationPolicy Tests")
struct PkixRevocationPolicyTests {
    let root: Data
    let leaf: Data

    init() throws {
        root = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-root", withExtension: "der")))
        leaf = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-leaf", withExtension: "der")))
    }

    @Test("Each policy maps to the matching iOS revocation method")
    func mapsToRevocationMethod() {
        #expect(PkixRevocationPolicy.disabled.iosRevocationMethod == nil)
        #expect(PkixRevocationPolicy.crlPriority.iosRevocationMethod === IosRevocationMethod.anyPreferCrl)
        #expect(PkixRevocationPolicy.crlOnly.iosRevocationMethod === IosRevocationMethod.crl)
        #expect(PkixRevocationPolicy.ocspPriority.iosRevocationMethod === IosRevocationMethod.anyPreferOcsp)
        #expect(PkixRevocationPolicy.ocspOnly.iosRevocationMethod === IosRevocationMethod.ocsp)
    }

    @Test("Only the disabled policy skips the revocation check", arguments: PkixRevocationPolicy.allCases)
    func isEnabled(policy: PkixRevocationPolicy) {
        #expect(policy.isEnabled == (policy != .disabled))
    }

    @Test("The legacy flag keeps its behaviour: true is OCSP only, false is disabled")
    func legacyFlagMapping() {
        #expect(PkixRevocationPolicy(isRevocationEnabled: true) == .ocspOnly)
        #expect(PkixRevocationPolicy(isRevocationEnabled: false) == .disabled)
    }

    @Test("New initializers default to OCSP only")
    func defaultsToOcspOnly() {
        #expect(EtsiTrustSource(loteLocations: Self.emptyLists).revocationPolicy == .ocspOnly)
        #expect(StaticListTrustSource(rootCertificates: [root]).revocationPolicy == .ocspOnly)
        #expect(StaticListTrustSource(anchorsPerContext: [.wrpac: [root]]).revocationPolicy == .ocspOnly)
    }

    @Test("Deprecated initializers map the legacy flag onto a policy")
    @available(*, deprecated, message: "Exercises the deprecated isRevocationEnabled API")
    func deprecatedInitializers() {
        let sources = LegacySources(lists: Self.emptyLists, root: root)
        #expect(sources.etsi(true).revocationPolicy == .ocspOnly)
        #expect(sources.etsi(false).revocationPolicy == .disabled)
        #expect(sources.staticRoots(true).revocationPolicy == .ocspOnly)
        #expect(sources.staticRoots(false).revocationPolicy == .disabled)
        #expect(sources.staticAnchors(true).revocationPolicy == .ocspOnly)
        #expect(sources.staticAnchors(false).revocationPolicy == .disabled)
        #expect(sources.isRevocationEnabled(StaticListTrustSource(rootCertificates: [root], revocationPolicy: .crlOnly)))
        #expect(!sources.isRevocationEnabled(StaticListTrustSource(rootCertificates: [root], revocationPolicy: .disabled)))
    }

    @Test("Replacing the context type mappings keeps the revocation policy", arguments: PkixRevocationPolicy.allCases)
    func withContextTypeMappingsKeepsPolicy(policy: PkixRevocationPolicy) {
        let mappings: EtsiContextTypeMappings = ["org.iso.18013.5.1.mDL": .mdl]
        let checker = UnknownCrlChecker()
        let etsi = TrustSource.etsi(EtsiTrustSource(loteLocations: Self.emptyLists, revocationPolicy: policy, crlChecker: checker))
        let staticList = TrustSource.staticList(StaticListTrustSource(rootCertificates: [root], revocationPolicy: policy, crlChecker: checker))
        guard case .etsi(let copiedEtsi) = etsi.withContextTypeMappings(mappings),
              case .staticList(let copiedStatic) = staticList.withContextTypeMappings(mappings) else {
            Issue.record("withContextTypeMappings changed the trust source kind")
            return
        }
        #expect(copiedEtsi.revocationPolicy == policy)
        #expect(copiedStatic.revocationPolicy == policy)
        #expect(copiedStatic.contextTypeMappings?["org.iso.18013.5.1.mDL"] == .mdl)
        #expect(copiedEtsi.crlChecker === checker)
        #expect(copiedStatic.crlChecker === checker)
    }

    @Test("Bundled anchors with CRL revocation reject a chain whose certificates publish no CRL")
    func crlOnlyRejectsChainWithoutCrl() async {
        // The test certificates carry no CRL distribution point, so the CRL checker cannot establish a status.
        let source = TrustSource.staticList(StaticListTrustSource(rootCertificates: [root], revocationPolicy: .crlOnly, crlChecker: UnknownCrlChecker()))
        let manager = EtsiTrustManager(source: source, defaultVerificationContext: EtsiContextType.wrpac.verificationContext)
        let (isTrusted, _) = await manager.validateCertTrustPath(chain: [leaf])
        #expect(!isTrusted)
    }

    private static var emptyLists: SupportedLists<NSString> {
        SupportedLists<NSString>(
            pidProviders: nil, walletProviders: nil, wrpacProviders: nil, wrprcProviders: nil,
            pubEaaProviders: nil, qeaProviders: nil, eaaProviders: [:]
        )
    }
}

/// Calls the deprecated API from a deprecated context, so the tests build without deprecation warnings.
@available(*, deprecated)
private struct LegacySources {
    let lists: SupportedLists<NSString>
    let root: Data

    func etsi(_ isRevocationEnabled: Bool) -> EtsiTrustSource {
        EtsiTrustSource(loteLocations: lists, isRevocationEnabled: isRevocationEnabled)
    }

    func staticRoots(_ isRevocationEnabled: Bool) -> StaticListTrustSource {
        StaticListTrustSource(rootCertificates: [root], isRevocationEnabled: isRevocationEnabled)
    }

    func staticAnchors(_ isRevocationEnabled: Bool) -> StaticListTrustSource {
        StaticListTrustSource(anchorsPerContext: [.wrpac: [root]], isRevocationEnabled: isRevocationEnabled)
    }

    func isRevocationEnabled(_ source: StaticListTrustSource) -> Bool {
        source.isRevocationEnabled
    }
}

/// A CRL checker that never establishes a status, as for certificates without a CRL distribution point.
final class UnknownCrlChecker: NSObject, CheckRevocationIos {
    func invoke(certificate: Data, issuer: Data) -> any IosRevocationStatus {
        IosRevocationStatusUnknown(reason: "No CRL in test")
    }
}
#endif
