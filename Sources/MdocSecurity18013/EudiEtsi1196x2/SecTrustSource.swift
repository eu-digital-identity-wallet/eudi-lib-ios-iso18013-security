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
import Security

/// A trust source backed by the platform Security framework: it validates certificate chains
/// against a set of bundled root (IACA) anchors via `SecurityHelpers.isMdocX5cValid`, with no
/// LoTE download and no network beyond CRL fetches.
/// Can be used in non-iOS platforms where EudiEtsi1196x2 module is not available .
public struct SecTrustSource: CertificateTrustValidator, @unchecked Sendable {
    /// DER-encoded trust anchor chains; each inner array is a root chain with the root last.
    public let rootIaca: [[Data]]
    /// The certificate usage the chain is validated for.
    public let usage: CertificateUsage
    /// The CRL revocation policy applied during validation.
    public let revocationPolicy: RevocationPolicy
    /// The document type currently being validated (unused by `isMdocX5cValid`, kept for protocol conformance).
    public var docType: String?

    public init(
        rootIaca: [[Data]],
        usage: CertificateUsage = .mdocAuth,
        revocationPolicy: RevocationPolicy = .warning,
        docType: String? = nil
    ) {
        self.rootIaca = rootIaca
        self.usage = usage
        self.revocationPolicy = revocationPolicy
        self.docType = docType
    }

    public func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) {
        guard let result = evaluate(chain: chain) else {
            return (false, "Invalid certificate in chain")
        }
        return (result.isValid, result.isValid ? nil : result.validationMessages.joined(separator: "; "))
    }

    public func createCertTrustPath(chain: [Data]) async -> [Data]? {
        guard let result = evaluate(chain: chain), result.isValid else { return nil }
        // Append the matched root anchor to complete the path when it is not already present.
        var path = chain
        if let rootCert = result.rootCert {
            let rootData = SecCertificateCopyData(rootCert) as Data
            if !chain.contains(rootData) { path.append(rootData) }
        }
        return path
    }

    /// Converts the DER chain and anchors to `SecCertificate`s and runs `isMdocX5cValid`.
    /// Returns `nil` when any DER entry cannot be decoded.
    private func evaluate(
        chain: [Data]
    ) -> (isValid: Bool, validationMessages: [String], rootCert: SecCertificate?)? {
        let secCerts = chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard secCerts.count == chain.count else { return nil }
        let roots: [x5chain] = rootIaca.map { $0.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) } }
        return SecurityHelpers.isMdocX5cValid(
            secCerts: secCerts, usage: usage,
            revocationPolicy: revocationPolicy,
            rootIaca: roots
        )
    }
}
