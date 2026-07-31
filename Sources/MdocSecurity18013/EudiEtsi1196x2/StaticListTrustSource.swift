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
import EudiEtsi1196x2

/// Configuration for a **static** trust source: a fixed set of DER-encoded root/anchor
/// certificates bundled with the app, validated with no LoTE download and no network.
///
/// This is the iOS counterpart of the "classic" pre-LoTE flow — bundling root certificates and
/// validating credential chains against them via `EudiwIosTrust.usingBundledAnchors`.
public struct StaticListTrustSource: @unchecked Sendable {
    /// DER-encoded trust anchors, keyed by the verification context they anchor.
    public let anchorsPerContext: [EtsiContextType: [Data]]
    /// The chain-validation strategy: `.pkix` for chain-to-anchor path validation (anchors are CA
    /// certificates) or `.directTrust` for leaf pinning (anchors are the exact end-entity certs).
    public let method: BundledAnchorMethod
    /// Doc-type → context mappings used to select the verification context per document.
    public let contextTypeMappings: EtsiContextTypeMappings?

    public init(
        anchorsPerContext: [EtsiContextType: [Data]],
        method: BundledAnchorMethod = .pkix,
        contextTypeMappings: EtsiContextTypeMappings? = nil
    ) {
        self.anchorsPerContext = anchorsPerContext
        self.method = method
        self.contextTypeMappings = contextTypeMappings
    }

    /// Convenience initializer for a single list of root certificates anchoring one context.
    ///
    /// - Parameters:
    ///   - rootCertificates: DER-encoded anchor certificates.
    ///   - context: the verification context these anchors apply to (default: WRPAC, the
    ///     Wallet Relying Party access certificate a reader presents).
    public init(
        rootCertificates: [Data],
        method: BundledAnchorMethod = .pkix,
        contextTypeMappings: EtsiContextTypeMappings? = nil
    ) {
        self.init(
            anchorsPerContext: [.pid: rootCertificates, .mdl: rootCertificates, .wallet: rootCertificates, .wrpac: rootCertificates, .wrprc: rootCertificates],
            method: method,
            contextTypeMappings: contextTypeMappings
        )
    }

    /// Builds the `BundledAnchors` payload for `EudiwIosTrust.usingBundledAnchors`.
    var bundledAnchors: BundledAnchors {
        let anchors = BundledAnchors()
        for (context, certificates) in anchorsPerContext {
            switch context {
            case .pid: anchors.pid = certificates
            case .mdl: anchors.mdl = certificates
            case .wallet: anchors.wallet = certificates
            case .wrpac: anchors.wrpac = certificates
            case .wrprc: anchors.wrprc = certificates
            }
        }
        return anchors
    }
}
#endif
