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
import Security
import EudiEtsi1196x2

@testable import MdocSecurity18013

/// Tests for `EtsiTrustManager` using the eudiRef ETSI LoTE source.
/// These tests download live trust lists and require network access. The bundled
/// certificate is not known to be trusted by those lists, so the tests check that
/// the validation pipeline completes, the trust APIs agree, and an untrusted
/// certificate is rejected.
@Suite("EtsiTrustManager Tests")
struct EtsiTrustManagerTests {
    /// DER leaf certificate issued by the bundled test root.
    let leaf: Data

    init() throws {
        leaf = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-leaf", withExtension: "der")))
    }

    @Test("eudiRef ETSI: validation pipeline completes and the two trust APIs agree")
    func eudiRefEtsiCompletes() async {
        let manager = EtsiTrustManager(source: .etsi(.eudiRef))
        let (trusted, reason) = await manager.validateCertTrustPath(chain: [leaf])
        if let reason { print("eudiRef ETSI failure reason: \(reason)") }
        let path = await manager.createCertTrustPath(chain: [leaf])
        #expect((path != nil) == trusted)
    }

    @Test("eudiRef ETSI: an untrusted certificate is not trusted")
    func eudiRefEtsiRejectsUntrusted() async {
        let manager = EtsiTrustManager(source: .etsi(.eudiRef)) 
        let (trusted, reason) = await manager.validateCertTrustPath(chain: [leaf])
        if let reason { print("eudiRef ETSI failure reason: \(reason)") }
        #expect(trusted == false)
    }


}
#endif
