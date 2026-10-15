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

/// Tests for the bundled-anchors path with revocation disabled, which runs offline.
@Suite("StaticListTrustSource Tests")
struct StaticListTrustSourceTests {
    let root: Data
    let leaf: Data

    init() throws {
        root = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-root", withExtension: "der")))
        leaf = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-leaf", withExtension: "der")))
    }

    @Test("Each context type matches a freshly obtained context of its own kind", arguments: EtsiContextType.allCases)
    func contextTypeMatchesItsContext(type: EtsiContextType) {
        let matched = EtsiContextType.allCases.filter { $0.matches(type.verificationContext) }
        #expect(matched == [type])
    }

    @Test("A reader chain to a bundled anchor is trusted without a revocation check")
    func readerChainTrustedWithoutRevocation() async {
        let source = TrustSource.staticList(StaticListTrustSource(rootCertificates: [root], isRevocationEnabled: false))
        let manager = EtsiTrustManager(source: source.withContextTypeMappings(nil), defaultVerificationContext: EtsiContextType.wrpac.verificationContext)
        let (isTrusted, reason) = await manager.validateCertTrustPath(chain: [leaf])
        #expect(isTrusted, "\(reason ?? "")")
    }
}
#endif
