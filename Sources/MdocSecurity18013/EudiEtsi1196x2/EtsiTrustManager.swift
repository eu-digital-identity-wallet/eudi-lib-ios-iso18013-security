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

public final class EtsiTrustManager: @unchecked Sendable {
    // Type-erased validation over the selected trust source; returns `nil` if validation throws
    // or the context is unsupported. Bridges the two validator kinds (cached LoTE vs. bundled
    // anchors), which the `EudiEtsi1196x2` API exposes through different entry points.
    private let cachedValidator: CachedTrustValidator?
    private let validateChain: ([Data], any VerificationContext) async -> IosValidationResult?
    let contextTypeMappings: EtsiContextTypeMappings?
    public var docType: String?
    let defaultVerificationContext: (any VerificationContext)?

    // Fallback manager consulted when this manager cannot evaluate the chain.
    private let fallback: EtsiTrustManager?

    /// Builds a trust manager from the selected `TrustConfig`.
    ///
    /// - source: Trust source
    /// - `.etsi`: a cached LoTE validator via `EudiwIosTrust.cached(urls:ttlHours:verifyJwtSignature:)`,
    ///   which honors `loteLocations`, `cacheTtl`, and `customJwtSignatureVerifier`.
    /// - `.staticList`: a bundled-anchors validator via `EudiwIosTrust.usingBundledAnchors(anchors:method:)`
    ///   — no LoTE download, no network.
    /// - defaultVerificationContext
    /// - `fallback`: an optional manager used to validate the chain when this manager has no  verification context for the requested doc type.
    public init(source: TrustSource, defaultVerificationContext: (any VerificationContext)? = nil, fallback: EtsiTrustManager? = nil) {
        contextTypeMappings = source.contextTypeMappings
        self.defaultVerificationContext = defaultVerificationContext
        self.fallback = fallback
        switch source {
        case .etsi(let etsi):
            let lists = etsi.loteLocations
            let urls = TrustListUrls()
            urls.pidProviders = lists.pidProviders as String?
            urls.walletProviders = lists.walletProviders as String?
            urls.wrpacProviders = lists.wrpacProviders as String?
            urls.wrprcProviders = lists.wrprcProviders as String?
            urls.pubEaaProviders = lists.pubEaaProviders as String?
            urls.qeaProviders = lists.qeaProviders as String?
            urls.mdlProviders = lists.eaaProviders[EudiwIosTrust.shared.mdlUseCase] as String?

            let verifyJwtSignature: VerifyJwtSignature = etsi.customJwtSignatureVerifier ?? x5cVerifyJwtOrCwt.shared
            let validator = EudiwIosTrust.shared.cached(urls: urls, ttlHours: etsi.cacheTtlHours, verifyJwtSignature: verifyJwtSignature)
            validateChain = { chain, context in
                do {
                    let iosVal = try await validator.validate(chain: chain, context: context)
                    if let failReason = iosVal.failureReason { logger.warning("ETSI LoTE not trusted reason: \(failReason)")}
                    return iosVal
              } catch {
                    logger.error("ETSI LoTE chain validation failed: \(error)")
                    return nil
                }
            }
            cachedValidator = validator
        case .staticList(let staticList):
            let validator = EudiwIosTrust.shared.usingBundledAnchors(anchors: staticList.bundledAnchors, method: staticList.method)
            validateChain = { chain, context in
                do {
                    let iosVal = try await EudiwIosTrust.shared.validate(validator: validator, chain: chain, context: context)
                    if let failReason = iosVal.failureReason { logger.warning("Bundled-anchors not trusted reason: \(failReason)")}
                    return iosVal
                } catch {
                    logger.error("Bundled-anchors chain validation failed: \(error)")
                    return nil
                }
            }
            cachedValidator = nil
        }
    }

    /// The verification context this configuration validates certificate chains against
    /// (e.g. PID, Wallet, WRPAC). `EtsiTrustManager` uses it as its single trust context.
    public func getVerificationContext() -> (any VerificationContext)? {
        if let contextTypeMappings, let docType {
            guard let contType = contextTypeMappings[docType] else { return nil }
            return contType.verificationContext
        }
        return defaultVerificationContext
    }
}

// MARK: - ReaderTrustStore

extension EtsiTrustManager: CertificateTrustValidator {
    public func createCertTrustPath(chain: [Data]) async -> [Data]? {
        guard let result = await validate(chain: chain), result.isTrusted else { return nil }
        // Append the matched trust anchor to complete the path when it is not already present.
        var path = chain
        if let anchorData = result.matchedAnchor, !chain.contains(anchorData) {
            path.append(anchorData)
        }
        return path
    }

    public func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) {
        guard let result = await validate(chain: chain) else {
            return (false, "Certificate chain validation could not be evaluated")
        }
        return (result.isTrusted, result.failureReason)
    }

    /// Validates the chain against the configured trust source, deferring to the fallback manager
    /// when the primary validation cannot be evaluated (no verification context, no validator
    /// configured for the context, or the validator throws).
    private func validate(chain: [Data]) async -> IosValidationResult? {
        if let result = await validatePrimary(chain: chain) { return result }
        // Primary validation could not be evaluated — defer to the fallback manager if configured.
        guard let fallback else { return nil }
        fallback.docType = docType
        logger.info("Primary trust validation unavailable; delegating to fallback trust manager")
        return await fallback.validate(chain: chain)
    }

    /// Runs the async validator for the configured trust source. Returns `nil` if no verification
    /// context is available, the validator has no configuration for the context, or validation throws.
    private func validatePrimary(chain: [Data]) async -> IosValidationResult? {
        guard let verificationContext = getVerificationContext() else { return nil }
        logger.info("Validate chain with context \(verificationContext)")
        let iosRes = await validateChain(chain, verificationContext)
        if let iosRes, !iosRes.isTrusted, iosRes.failureReason == "No validator configured for this context" { return nil }
        return iosRes
    }
}

extension x5cVerifyJwtOrCwt: VerifyJwtSignature {
    public func invoke(jwt: String) async throws -> any VerifyJwtSignatureOutcome {
        let jws = try JWS(jwsString: jwt)
        try Self.verify(jws: jws)
        return VerifyJwtSignatureOutcomeVerified(jwt: jwt)
    }
}

#endif

