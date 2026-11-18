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
import OrderedCollections

/// The verification contexts the EUDI Reference Implementation environment exposes.
public enum EtsiContextType: String, CaseIterable, Identifiable, Sendable {
    case pid = "PID"
    case mdl = "mDL"
    case wallet = "Wallet"
    case wrpac = "WRPAC"
    case wrprc = "WRPRC"
    case qeaa = "QEAA"
    case pubEaa = "PubEAA"
    case pidStatus = "PIDStatus"
    case mdlStatus = "mDLStatus"
    case qeaaStatus = "QEAAStatus"
    case pubEaaStatus = "PubEAAStatus"
    case wrprcStatus = "WRPRCStatus"

    /// Status-signing context for an attestation or registration certificate.
    /// Access certificates and wallet attestations have no document status mapping here.
    public var statusContext: Self? {
        switch self {
        case .pid, .pidStatus: .pidStatus
        case .mdl, .mdlStatus: .mdlStatus
        case .qeaa, .qeaaStatus: .qeaaStatus
        case .pubEaa, .pubEaaStatus: .pubEaaStatus
        case .wrprc, .wrprcStatus: .wrprcStatus
        case .wallet, .wrpac: nil
        }
    }

    // The KMP bundled-anchor bridge only exposes issuance contexts. For static anchors,
    // select the exact status anchors first, then use the corresponding bridge slot.
    var bundledAnchorContext: Self {
        switch self {
        case .pidStatus: .pid
        case .mdlStatus: .mdl
        case .qeaaStatus: .qeaa
        case .pubEaaStatus: .pubEaa
        case .wrprcStatus: .wrprc
        default: self
        }
    }

    public var id: String { rawValue }

    public var verificationContext: VerificationContext {
        switch self {
        case .pid:    return VerificationContextPID.shared
        case .wallet: return VerificationContextWalletProviderAttestation.shared
        case .wrpac:  return VerificationContextWalletRelyingPartyAccessCertificate.shared
        case .wrprc:  return VerificationContextWalletRelyingPartyRegistrationCertificate.shared
        case .mdl: return VerificationContextEAA(useCase: EudiwIosTrust.shared.mdlUseCase)
        case .qeaa: return VerificationContextQEAA.shared
        case .pubEaa: return VerificationContextPubEAA.shared
        case .pidStatus: return VerificationContextPIDStatus.shared
        case .mdlStatus: return VerificationContextEAAStatus(useCase: EudiwIosTrust.shared.mdlUseCase)
        case .qeaaStatus: return VerificationContextQEAAStatus.shared
        case .pubEaaStatus: return VerificationContextPubEAAStatus.shared
        case .wrprcStatus: return VerificationContextWalletRelyingPartyRegistrationCertificateStatus.shared
        }
    }
}

extension EtsiContextType {
    /// Whether `context` is the verification context this type stands for. Matched by type:
    /// each `.shared` access on a Kotlin object returns a fresh Objective-C wrapper, so an
    /// identity check never matches. The mDL context is created per use case.
    func matches(_ context: any VerificationContext) -> Bool {
        switch self {
        case .pid: return context is VerificationContextPID
        case .mdl: return (context as? VerificationContextEAA)?.useCase == EudiwIosTrust.shared.mdlUseCase
        case .wallet: return context is VerificationContextWalletProviderAttestation
        case .wrpac: return context is VerificationContextWalletRelyingPartyAccessCertificate
        case .wrprc: return context is VerificationContextWalletRelyingPartyRegistrationCertificate
        case .qeaa: return context is VerificationContextQEAA
        case .pubEaa: return context is VerificationContextPubEAA
        case .pidStatus: return context is VerificationContextPIDStatus
        case .mdlStatus: return (context as? VerificationContextEAAStatus)?.useCase == EudiwIosTrust.shared.mdlUseCase
        case .qeaaStatus: return context is VerificationContextQEAAStatus
        case .pubEaaStatus: return context is VerificationContextPubEAAStatus
        case .wrprcStatus: return context is VerificationContextWalletRelyingPartyRegistrationCertificateStatus
        }
    }
}

public typealias EtsiContextTypeMappings = OrderedDictionary<String, EtsiContextType>

public extension OrderedDictionary where Key == String, Value == EtsiContextType {
    static let `default`: Self = ["eu.europa.ec.eudi.pid.1": .pid, "urn:eudi:pid:1": .pid, "org.iso.18013.5.1.mDL": .mdl]
}
#endif
