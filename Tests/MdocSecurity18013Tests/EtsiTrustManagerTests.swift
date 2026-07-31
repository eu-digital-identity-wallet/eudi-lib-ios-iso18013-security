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

/// Tests for `EtsiTrustManager` across its three trust sources.
///
/// - `digi` / `eudiRef` are ETSI LoTE sources: they download live trust lists, so their tests
///   require network access. There is no bundled certificate the live lists are known to trust,
///   so the "success" tests assert only that the validation pipeline **completes** and that the
///   two trust APIs agree — not a hard `trusted == true`. The failure tests assert that an
///   untrusted certificate is rejected (which also holds offline, since a download error yields
///   "not trusted").
/// - The static-list source is fully offline and deterministic: `eudi-test-root.der` issues
///   `eudi-test-leaf.der`, so both success (`true`) and failure (`false`) are asserted exactly.
@Suite("EtsiTrustManager Tests")
struct EtsiTrustManagerTests {
    /// DER leaf certificate issued by the bundled test root.
    let leaf: Data
    /// DER self-signed test root CA that issued `leaf`.
    let root: Data
    /// An unrelated DER certificate, used as an untrusted input.
    let untrusted: Data

    init() throws {
        leaf = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-leaf", withExtension: "der")))
        root = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-root", withExtension: "der")))
        untrusted = try Data(contentsOf: #require(Bundle.module.url(forResource: "pidissuerca02_ut", withExtension: "der")))
    }

    // MARK: - 1. digi (ETSI LoTE — requires network)

    @Test("digi ETSI: validation pipeline completes and the two trust APIs agree")
    func digiEtsiCompletes() async {
        let manager = EtsiTrustManager(source: .etsi(.digiTrust))
        let (trusted, reason) = await manager.validateCertTrustPath(chain: [leaf])
        if let reason { print("digi ETSI failure reason: \(reason)") }
        let path = await manager.createCertTrustPath(chain: [leaf])
        // `createCertTrustPath` returns a path iff the chain is trusted — invariant holds
        // regardless of the remote list's decision (or a network error).
        #expect((path != nil) == trusted)
    }

    @Test("digi ETSI: an untrusted certificate is not trusted")
    func digiEtsiRejectsUntrusted() async {
        let manager = EtsiTrustManager(source: .etsi(.digiTrust))
        let (trusted, reason) = await manager.validateCertTrustPath(chain: [leaf])
        if let reason { print("digi ETSI failure reason: \(reason)") }
        #expect(trusted == false)
    }

    // MARK: - 2. eudiRef (ETSI LoTE — requires network)

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

    // MARK: - 3. static list (offline — deterministic)

    @Test("static list: a leaf issued by the bundled root is trusted (PKIX)")
    func staticListTrustsLeaf() async {
        let staticSource = StaticListTrustSource(rootCertificates: [root], method: .pkix)
        let manager = EtsiTrustManager(source: .staticList(staticSource))
        let (trusted, reason) = await manager.validateCertTrustPath(chain: [leaf])
        if let reason { print("static list failure reason: \(reason)") }
        #expect(trusted)
        // The completed path includes the matched anchor (the root).
        let path = await manager.createCertTrustPath(chain: [leaf])
        #expect(path != nil)
        #expect(path?.contains(root) == true)
    }

    @Test("static list: an unrelated certificate is not trusted")
    func staticListRejectsUnrelated() async {
        let staticSource = StaticListTrustSource(rootCertificates: [root], method: .pkix)
        let manager = EtsiTrustManager(source: .staticList(staticSource))
        let (trusted, reason) = await manager.validateCertTrustPath(chain: [untrusted])
        if let reason { print("static list failure reason: \(reason)") }
        #expect(trusted == false)
        let path = await manager.createCertTrustPath(chain: [untrusted])
        #expect(path == nil)
    }
}
#endif
