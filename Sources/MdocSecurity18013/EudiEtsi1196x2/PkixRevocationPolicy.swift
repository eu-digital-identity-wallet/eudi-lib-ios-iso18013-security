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
import EudiEtsi1196x2

/// How PKIX certificate chain validation checks revocation.
///
/// Every enabled policy requires a positive revocation response
/// (`kSecRevocationRequirePositiveResponse`), so there is no soft-fail policy: a chain whose
/// revocation status cannot be obtained is not trusted.
public enum PkixRevocationPolicy: Sendable, CaseIterable {
    /// No revocation check.
    case disabled
    /// CRL first, OCSP as fallback (`IosRevocationMethod.anyPreferCrl`).
    case crlPriority
    /// CRL only (`IosRevocationMethod.crl`). Suits a PKI that publishes CRLs but runs no OCSP responder.
    case crlOnly
    /// OCSP first, CRL as fallback (`IosRevocationMethod.anyPreferOcsp`).
    case ocspPriority
    /// OCSP only (`IosRevocationMethod.ocsp`). The behaviour of `isRevocationEnabled: true`.
    case ocspOnly

    /// Whether revocation is checked at all.
    public var isEnabled: Bool { self != .disabled }

    /// The revocation method handed to the PKIX validator, or `nil` when revocation is disabled.
    var iosRevocationMethod: IosRevocationMethod? {
        switch self {
        case .disabled: nil
        case .crlPriority: .anyPreferCrl
        case .crlOnly: .crl
        case .ocspPriority: .anyPreferOcsp
        case .ocspOnly: .ocsp
        }
    }

    /// Maps the legacy `isRevocationEnabled` flag onto a policy without changing its behaviour.
    init(isRevocationEnabled: Bool) {
        self = isRevocationEnabled ? .ocspOnly : .disabled
    }

    /// A PKIX chain validator that checks revocation according to this policy. Every policy that
    /// uses CRLs needs `crlChecker`; without it the validator cannot be created.
    func pkixValidator(crlChecker: (any CheckRevocationIos)?) -> ValidateCertificateChainUsingPKIXIos {
        guard let iosRevocationMethod else {
            return ValidateCertificateChainUsingPKIXIos.companion.invoke(isRevocationEnabled: false)
        }
        if let crlChecker {
            return ValidateCertificateChainUsingPKIXIos.companion.invoke(revocationMethod: iosRevocationMethod, checkCrlRevocation: crlChecker)
        }
        return ValidateCertificateChainUsingPKIXIos.companion.invoke(revocationMethod: iosRevocationMethod, isRevocationEnabled: true)
    }
}
#endif
