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

import XCTest
import X509
import SwiftASN1

@testable import MdocDataModel18013
@testable import MdocSecurity18013

final class CertificateHandlingTests: XCTestCase {
    var certData: Data!

    override func setUpWithError() throws {
        try super.setUpWithError()
        certData = try Data(contentsOf: Bundle.module.url(forResource: "owf_identity_credential_reader_cert", withExtension: "der")!)
    }

	func testReaderCertificateValidations() throws {
		let certObj = try X509.Certificate(derEncoded: [UInt8](certData))
		print("Certificate subject:", certObj.subject.description)
		let cert = try XCTUnwrap(SecCertificateCreateWithData(nil, certData as CFData))
		let (isValid, messages, _) = SecurityHelpers.isMdocX5cValid(secCerts: [cert], usage: .mdocReaderAuth, rootCerts: [])
		XCTAssert(!isValid) // no root certs given
		print("Validation messages", messages)
	}
	
	func testCRLParsing() throws {
		let pemStr = try String(contentsOf: Bundle.module.url(forResource: "test", withExtension: "crl")!)
		let crl = try CRL(pemEncoded: pemStr)
		print(crl.revokedSerials.map(\.description))
	}

}
