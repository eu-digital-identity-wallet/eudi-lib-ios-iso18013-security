/*
Copyright (c) 2023 European Commission

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
import Testing
import X509
import Security

@testable import MdocDataModel18013
@testable import MdocSecurity18013

@Suite("Certificate Handling Tests")
struct CertificateHandlingTests {
    var certData: Data

    init() throws {
        certData = try Data(contentsOf: Bundle.module.url(forResource: "owf_identity_credential_reader_cert", withExtension: "der")!)
    }

	@Test("Reader certificate validations")
	func readerCertificateValidations() throws {
		let certObj = try X509.Certificate(derEncoded: [UInt8](certData))
		print("Certificate subject:", certObj.subject.description)
		let cert = try #require(SecCertificateCreateWithData(nil, certData as CFData))
		let (isValid, messages, _) = SecurityHelpers.isMdocX5cValid(secCerts: [cert], usage: .mdocReaderAuth, rootCerts: [])
		#expect(!isValid) // no root certs given
		print("Validation messages", messages)
	}

	@Test("CRL parsing")
	func crlParsing() throws {
		let pemStr = try String(contentsOf: Bundle.module.url(forResource: "test", withExtension: "crl")!)
		let crl = try CRL(pemEncoded: pemStr)
		print(crl.revokedSerials.map(\.description))
	}

}
