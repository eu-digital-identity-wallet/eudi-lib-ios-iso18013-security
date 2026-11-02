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
    /// How chain validation checks revocation. With `.disabled` the chain is evaluated against
    /// the anchors without a revocation check; every other policy requires a positive response
    /// from the configured CRL / OCSP method. Mirrors `EtsiTrustSource.revocationPolicy`.
    public let revocationPolicy: PkixRevocationPolicy

    /// Whether chain validation checks revocation.
    @available(*, deprecated, message: "Use revocationPolicy instead")
    public var isRevocationEnabled: Bool { revocationPolicy.isEnabled }

    public init(
        anchorsPerContext: [EtsiContextType: [Data]],
        method: BundledAnchorMethod = .pkix,
        contextTypeMappings: EtsiContextTypeMappings? = nil,
        revocationPolicy: PkixRevocationPolicy = .crlPriority
    ) {
        self.anchorsPerContext = anchorsPerContext
        self.method = method
        self.contextTypeMappings = contextTypeMappings
        self.revocationPolicy = revocationPolicy
    }

    /// Convenience initializer for a single list of root certificates anchoring every context.
    ///
    /// - Parameters:
    ///   - rootCertificates: DER-encoded anchor certificates.
    ///   - method: the chain-validation strategy.
    ///   - contextTypeMappings: doc-type → context mappings.
    ///   - revocationPolicy: how chain validation checks revocation.
    public init(
        rootCertificates: [Data],
        method: BundledAnchorMethod = .pkix,
        contextTypeMappings: EtsiContextTypeMappings? = nil,
        revocationPolicy: PkixRevocationPolicy = .crlPriority
    ) {
        self.init(
            anchorsPerContext: Self.anchorsForEveryContext(rootCertificates),
            method: method,
            contextTypeMappings: contextTypeMappings,
            revocationPolicy: revocationPolicy
        )
    }

    /// Creates a source from the legacy revocation flag: `true` requires a positive OCSP response
    /// (`.ocspOnly`), `false` skips the revocation check (`.disabled`).
    @available(*, deprecated, message: "Use init(anchorsPerContext:method:contextTypeMappings:revocationPolicy:) instead")
    public init(
        anchorsPerContext: [EtsiContextType: [Data]],
        method: BundledAnchorMethod = .pkix,
        contextTypeMappings: EtsiContextTypeMappings? = nil,
        isRevocationEnabled: Bool
    ) {
        self.init(
            anchorsPerContext: anchorsPerContext,
            method: method,
            contextTypeMappings: contextTypeMappings,
            revocationPolicy: PkixRevocationPolicy(isRevocationEnabled: isRevocationEnabled)
        )
    }

    /// Creates a source from the legacy revocation flag: `true` requires a positive OCSP response
    /// (`.ocspOnly`), `false` skips the revocation check (`.disabled`).
    @available(*, deprecated, message: "Use init(rootCertificates:method:contextTypeMappings:revocationPolicy:) instead")
    public init(
        rootCertificates: [Data],
        method: BundledAnchorMethod = .pkix,
        contextTypeMappings: EtsiContextTypeMappings? = nil,
        isRevocationEnabled: Bool
    ) {
        self.init(
            anchorsPerContext: Self.anchorsForEveryContext(rootCertificates),
            method: method,
            contextTypeMappings: contextTypeMappings,
            revocationPolicy: PkixRevocationPolicy(isRevocationEnabled: isRevocationEnabled)
        )
    }

    private static func anchorsForEveryContext(_ rootCertificates: [Data]) -> [EtsiContextType: [Data]] {
        [.pid: rootCertificates, .mdl: rootCertificates, .wallet: rootCertificates, .wrpac: rootCertificates, .wrprc: rootCertificates]
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
