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
import Security
import EudiEtsi1196x2

/// Evaluates a certificate chain against bundled trust anchors without a revocation check:
/// PKIX path validation with the anchors as the only trusted roots (`.pkix`), or leaf
/// pinning against the exact anchor certificates (`.directTrust`).
enum BundledAnchorsValidator {
    static func validate(chain: [Data], anchors: [Data], method: BundledAnchorMethod) -> IosValidationResult {
        guard let leaf = chain.first else {
            return IosValidationResult(isTrusted: false, matchedAnchor: nil, failureReason: "Certificate chain is empty")
        }
        if method == BundledAnchorMethod.directTrust {
            guard let pinned = anchors.first(where: { $0 == leaf }) else {
                return IosValidationResult(isTrusted: false, matchedAnchor: nil, failureReason: "Leaf certificate is not one of the pinned anchors")
            }
            return IosValidationResult(isTrusted: true, matchedAnchor: pinned, failureReason: nil)
        }
        let certs = chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        let anchorCerts = anchors.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certs.count == chain.count, anchorCerts.count == anchors.count else {
            return IosValidationResult(isTrusted: false, matchedAnchor: nil, failureReason: "Invalid certificate in chain or anchors")
        }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certs as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let secTrust = trust,
              SecTrustSetAnchorCertificates(secTrust, anchorCerts as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(secTrust, true) == errSecSuccess else {
            return IosValidationResult(isTrusted: false, matchedAnchor: nil, failureReason: "Trust evaluation could not be set up")
        }
        var cfError: CFError?
        guard SecTrustEvaluateWithError(secTrust, &cfError) else {
            let reason = cfError.map { ($0 as Error).localizedDescription } ?? "Trust evaluation failed"
            return IosValidationResult(isTrusted: false, matchedAnchor: nil, failureReason: reason)
        }
        let matched = (SecTrustCopyCertificateChain(secTrust) as? [SecCertificate])?.last.map { SecCertificateCopyData($0) as Data }
        return IosValidationResult(isTrusted: true, matchedAnchor: matched, failureReason: nil)
    }
}
#endif
