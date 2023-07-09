import Foundation
import CryptoKit
import MdocDataModel18013

extension SessionEncryption {
	
	public func makeDetachedCoseMac0(payloadData: Data, key: SymmetricKey, alg: Cose.MacAlgorithm) -> Cose {
		let coseIn = Cose(type: .mac0, algorithm: alg.rawValue, payloadData: payloadData)
		let dataToSign = coseIn.signatureStruct!
		// return COSE_MAC0 struct
		return Cose(type: .mac0, algorithm: alg.rawValue, signature: computeMACValue(dataToSign, key: key, alg: alg))
	}
	
	public func computeMACValue(_ dataToAuthenticate: Data, key: SymmetricKey, alg: Cose.MacAlgorithm) -> Data {
		let mac0Value: Data
		switch alg {
		case .hmac256:
            let hashCode = CryptoKit.HMAC<SHA256>.authenticationCode(for: dataToAuthenticate, using: key)
			mac0Value = hashCode.withUnsafeBytes{ (p: UnsafeRawBufferPointer) -> Data in  Data(p[0..<p.count]) }
		case .hmac384:
            let hashCode = CryptoKit.HMAC<SHA384>.authenticationCode(for: dataToAuthenticate, using: key)
			mac0Value = hashCode.withUnsafeBytes{ (p: UnsafeRawBufferPointer) -> Data in  Data(p[0..<p.count]) }
		case .hmac512:
            let hashCode = CryptoKit.HMAC<SHA512>.authenticationCode(for: dataToAuthenticate, using: key)
			mac0Value = hashCode.withUnsafeBytes{ (p: UnsafeRawBufferPointer) -> Data in  Data(p[0..<p.count]) }
		}
		return mac0Value
	}
}