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
import Testing
import Security

@testable import MdocSecurity18013

/// Tests for `SecTrustSource` which validates certificate chains against bundled root anchors
/// using the platform Security framework (`SecurityHelpers.isMdocX5cValid`).
///
/// Uses the same bundled test certificates as `EtsiTrustManagerTests`:
/// - `eudi-test-root.der`: self-signed test root CA
/// - `eudi-test-leaf.der`: leaf certificate issued by the test root
/// - `pidissuerca02_ut.der`: an unrelated certificate used as untrusted input
@Suite("SecTrustSource Tests")
struct SecTrustSourceTests {
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

    // MARK: - validateCertTrustPath

    @Test("a leaf issued by the bundled root is trusted")
    func validateTrustsLeafIssuedByRoot() async {
        let source = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        let (trusted, reason) = await source.validateCertTrustPath(chain: [leaf])
        if let reason { print("SecTrustSource failure reason: \(reason)") }
        #expect(trusted)
    }

    @Test("an unrelated certificate is not trusted")
    func validateRejectsUnrelated() async {
        let source = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        let (trusted, _) = await source.validateCertTrustPath(chain: [untrusted])
        #expect(trusted == false)
    }

    @Test("an empty chain is not trusted")
    func validateRejectsEmptyChain() async {
        let source = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        let (trusted, reason) = await source.validateCertTrustPath(chain: [])
        #expect(trusted == false)
        #expect(reason != nil)
    }

    @Test("invalid DER data is not trusted")
    func validateRejectsInvalidDER() async {
        let source = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        let garbage = Data([0x00, 0x01, 0x02, 0x03])
        let (trusted, reason) = await source.validateCertTrustPath(chain: [garbage])
        #expect(trusted == false)
        #expect(reason != nil)
    }

    // MARK: - createCertTrustPath

    @Test("createCertTrustPath returns a path including the root for a trusted leaf")
    func createPathIncludesRoot() async {
        let source = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        let path = await source.createCertTrustPath(chain: [leaf])
        #expect(path != nil)
        #expect(path?.contains(root) == true)
    }

    @Test("createCertTrustPath returns nil for an untrusted certificate")
    func createPathReturnsNilForUntrusted() async {
        let source = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        let path = await source.createCertTrustPath(chain: [untrusted])
        #expect(path == nil)
    }

    @Test("createCertTrustPath returns nil for an empty chain")
    func createPathReturnsNilForEmptyChain() async {
        let source = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        let path = await source.createCertTrustPath(chain: [])
        #expect(path == nil)
    }

    // MARK: - Revocation policy variants

    @Test("warning revocation policy still trusts a valid leaf")
    func warningRevocationPolicyTrustsLeaf() async {
        let source = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        let (trusted, _) = await source.validateCertTrustPath(chain: [leaf])
        #expect(trusted)
    }

    // MARK: - Multiple root anchors

    @Test("validates against the correct root when multiple anchors are provided")
    func multipleAnchors() async {
        let source = SecTrustSource(rootIaca: [[root], [untrusted]], usage: .mdocAuth, revocationPolicy: .warning)
        let (trusted, _) = await source.validateCertTrustPath(chain: [leaf])
        #expect(trusted)
    }
}
