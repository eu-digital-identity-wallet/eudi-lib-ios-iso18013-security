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
import JSONWebSignature
import X509

/// Authenticates the signer against the configured LoTE anchors before verifying its JWS.
final class LoteJwtVerifier: VerifyJwtSignature, Sendable {
    private let signerTrustAnchors: [Data]

    init(signerTrustAnchors: [Data]) {
        self.signerTrustAnchors = signerTrustAnchors
    }

    func invoke(jwt: String) async throws -> any VerifyJwtSignatureOutcome {
        do {
            guard !signerTrustAnchors.isEmpty,
                  signerTrustAnchors.allSatisfy({ SecCertificateCreateWithData(nil, $0 as CFData) != nil }) else {
                return VerifyJwtSignatureOutcomeNotVerified(cause: nil)
            }
            let jws = try JWS(jwsString: jwt)
            let header = jws.protectedHeader
            guard header.critical == nil, header.base64EncodedUrlPayload != false,
                  let entries = header.x509CertificateChain else {
                return VerifyJwtSignatureOutcomeNotVerified(cause: nil)
            }
            switch header.algorithm {
            case .ES256, .ES384, .ES512, .ES256K, .RS256, .RS384, .RS512, .PS256, .PS384, .PS512, .EdDSA:
                break
            default:
                return VerifyJwtSignatureOutcomeNotVerified(cause: nil)
            }
            let chain = entries.compactMap { Data(base64Encoded: $0) }
            guard chain.count == entries.count, let leaf = chain.first,
                  try isTrustedSigner(leaf, chain: chain) else {
                return VerifyJwtSignatureOutcomeNotVerified(cause: nil)
            }
            try x5cVerifyJwtOrCwt.verify(jws: jws)
            return VerifyJwtSignatureOutcomeVerified(jwt: jwt)
        } catch {
            logger.warning("LoTE JWT verification failed: \(error)")
            return VerifyJwtSignatureOutcomeNotVerified(cause: nil)
        }
    }

    private func isTrustedSigner(_ leaf: Data, chain: [Data]) throws -> Bool {
        let certificate = try Certificate(derEncoded: Array(leaf))
        let now = Date()
        guard certificate.notValidBefore <= now, now <= certificate.notValidAfter else { return false }
        if signerTrustAnchors.contains(leaf) {
            return chain.allSatisfy { SecCertificateCreateWithData(nil, $0 as CFData) != nil }
        }
        let result = BundledAnchorsValidator.validate(
            chain: chain, anchors: signerTrustAnchors, method: .pkix, disableNetworkFetch: true
        )
        guard result.isTrusted, let anchor = result.matchedAnchor else { return false }
        return signerTrustAnchors.contains(anchor)
    }
}
#endif
