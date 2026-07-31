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
import JSONWebSignature
import MdocDataModel18013

/// An enumeration that defines an attest token.
///
public enum AttestToken {
    /// This enum is used to specify whether the attest token is in JSON Web Token (JWT) format or CWT format.
    public enum Format: String, Sendable {
      /// Represents the JSON Web Token (JWT) format.
      case jwt
      /// Represents the CWT format.
      case cwt
    }
    
    case cwt(ReaderAuth)
    case jwt(JWS)
    
    
    public var format: Format {
        switch self {
            case .cwt: return .cwt
        	case .jwt: return .jwt
        }
    }
}


