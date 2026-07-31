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

//  LoTE trust-list endpoints (EC DIGIT acceptance environment).
struct DIGITTrustLists {
    static let baseUrl = "https://acceptance.trust.tech.ec.europa.eu/lists/eudiw"

    static let pidProviders = "\(baseUrl)/pid-providers.json"
    static let walletProviders = "\(baseUrl)/wallet-providers.json"
    static let wrpacProviders = "\(baseUrl)/wrpac-providers.json"
    static let mdlProviders = "\(baseUrl)/mdl-providers.json"
}

// LoTE trust-list endpoints for the EUDI Wallet Reference Implementation environment.
// No mDL list (the ref-impl env doesn't publish one); has WRPRC instead.
struct EUDIRefImplLists {
    static let baseUrl = "https://trustedlist.serviceproviders.eudiw.dev/LOTE/json"

    static let pidProviders = "\(baseUrl)/PIDProviders.jwt"
    static let walletProviders = "\(baseUrl)/WalletProviders.jwt"
    static let wrpacProviders = "\(baseUrl)/WRPACProviders.jwt"
    static let wrprcProviders = "\(baseUrl)/WRPRCProviders.jwt"
}
#endif
