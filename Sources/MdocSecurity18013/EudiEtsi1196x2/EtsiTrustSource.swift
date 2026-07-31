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

/// Configuration for the ETSI LoTE (List of Trusted Entities) trust infrastructure.
///
/// This centralizes the LoTE pipeline parameters so that the core can build the ETSI
/// trust source internally, eliminating the need for consumers to construct the ETSI
/// library plumbing themselves.
public struct EtsiTrustSource: @unchecked Sendable {
    /// The LoTE download locations (e.g., PID, PubEAA, WRPAC provider URLs).
    public let loteLocations: SupportedLists<NSString>
    // verification context mappings (doc type to etsi context)
    public let contextTypeMappings: EtsiContextTypeMappings?
    /// Optional custom JWT signature verifier for LoTE JWTs; when `nil`, the core uses
    /// its built-in verifier.
    public let customJwtSignatureVerifier: (any VerifyJwtSignature)?
    /// Controls whether additional LoTE pointers are followed.
    public let loteConstraints: any LoadLoTEAndPointersConstraints

    /// How long downloaded LoTE files are cached on disk by default (24 hours).
    public static let defaultCacheTtlHours: TimeInterval = 24

    /// `cacheTtlHours` expressed in hours, for the `EudiwIosTrust.cached(ttlHours:)` boundary.
    public let cacheTtlHours: Double

    public init(
        loteLocations: SupportedLists<NSString>,
        contextTypeMappings: EtsiContextTypeMappings? = nil,
        cacheTtlHours: TimeInterval = EtsiTrustSource.defaultCacheTtlHours,
        customJwtSignatureVerifier: (any VerifyJwtSignature)? = nil,
        loteConstraints: any LoadLoTEAndPointersConstraints = LoadLoTEAndPointersConstraintsDoNotLoadOtherPointers.shared
    ) {
        self.loteLocations = loteLocations
        self.contextTypeMappings = contextTypeMappings
        self.cacheTtlHours = cacheTtlHours
        self.customJwtSignatureVerifier = customJwtSignatureVerifier
        self.loteConstraints = loteConstraints
    }
}

// MARK: - Ready-made environment presets

extension EtsiTrustSource {
    /// LoTE trust lists for the EC DIGIT acceptance environment (PID, Wallet, WRPAC, mDL).
    ///
    /// certificate a reader presents. Build `EtsiTrustConfig` directly to target another context.
    public static var digiTrust: Self { Self(loteLocations: SupportedLists<NSString>(
                pidProviders: DIGITTrustLists.pidProviders as NSString,
                walletProviders: DIGITTrustLists.walletProviders as NSString,
                wrpacProviders: DIGITTrustLists.wrpacProviders as NSString,
                wrprcProviders: nil,
                pubEaaProviders: nil,
                qeaProviders: nil,
                eaaProviders: [EudiwIosTrust.shared.mdlUseCase: DIGITTrustLists.mdlProviders as NSString]
            )
        )
    }

    /// LoTE trust lists for the EUDI Wallet Reference Implementation environment
    /// (PID, Wallet, WRPAC, WRPRC; no mDL list is published there).
    ///
    /// certificate a reader presents. Build `EtsiTrustConfig` directly to target another context.
    public static var eudiRef: Self {Self(loteLocations: SupportedLists<NSString>(
                pidProviders: EUDIRefImplLists.pidProviders as NSString,
                walletProviders: EUDIRefImplLists.walletProviders as NSString,
                wrpacProviders: EUDIRefImplLists.wrpacProviders as NSString,
                wrprcProviders: EUDIRefImplLists.wrprcProviders as NSString,
                pubEaaProviders: nil,
                qeaProviders: nil,
                eaaProviders: [:]
            )
        )
    }
}
#endif
