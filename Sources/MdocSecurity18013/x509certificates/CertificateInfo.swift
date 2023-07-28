//
//  mDLReaderDemo
//
import Foundation
import ASN1Decoder
import CryptoKit

public class CertificateInfo: CustomDebugStringConvertible {
    let ref: SecCertificate
    
  public init(ref: SecCertificate) {
    self.ref = ref
  }
  
  lazy public var commonName: String? = {
    var cfName: CFString?
    SecCertificateCopyCommonName(ref, &cfName)
    return cfName as String?
  }()
  
  lazy public var subjectSummary: String? = {
    var cfSummary: CFString?
    cfSummary = SecCertificateCopySubjectSummary(ref)
    return cfSummary as String?
  }()
  
  lazy public var email: String? = {
    var cfEmails: CFArray?
    SecCertificateCopyEmailAddresses(ref, &cfEmails)
    guard let emails = cfEmails as! Array<String>? else {return nil}
    return emails.count > 0 ? emails[0] : ""
  }()
  
  lazy public var thumbprint: String = {
    let der = SecCertificateCopyData(ref) as Data
    return Array(Insecure.SHA1.hash(data: der)).reduce(into: "") {
      var s = String($1, radix: 16)
      if s.count == 1 {s = "0" + s}
      if $0.count > 0 { $0 += ":" }
      if $0.count == 39 { $0 += " " }
      $0 += s.uppercased()
    }
  }()
  
  
  lazy public var serialNumber: String = {
    var cfError: Unmanaged<CFError>?
    guard let snRef = SecCertificateCopySerialNumberData(ref, &cfError) else { return "" }
    return (snRef as Data).bytes.toHexString().uppercased()
  }()
  
  lazy public var expiryDate: Date? = {
    guard let x509 = try? X509Certificate(der: SecCertificateCopyData(ref) as Data) else { return nil }
    return x509.notAfter
  }()
  
  func trustIsValid(_ trust: SecTrust) -> Bool {
    var error: CFError?
    let isValid = SecTrustEvaluateWithError(trust, &error)
    return isValid
  }
  
  public var failed: Bool?
  
  public func getValidityPeriod() -> (Date, Date)? {
    let certData = SecCertificateCopyData(ref) as Data
    guard let x509 = try? X509Certificate(data: certData) else { return nil }
    guard let vad = x509.notBefore, let vud = x509.notAfter else { return nil }
    return (vad,vud)
  }
  
  public var debugDescription: String {
    return "Certificate(ref=\(ref))"
  }
  
  public static func getCertInfo(certData: Data?) -> (SecCertificate?, CertificateInfo?) {
    guard let certificateData = certData else {return (nil,nil) }
    guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {return (nil,nil) }
    let cert = CertificateInfo(ref: certificate)
    return (certificate,cert)
  }
  
}

enum CertDataElement: String {
  case serialNumber = "certificate_serial_number"
  case publicKeyAlgorithm = "certificate_public_key_algorithm"
  case signatureAlgorithm = "certificate_signature_algorithm"
  case thumbprint = "certificate_thumbprint"
  case issuer = "certificate_issuer"
  case subject = "certificate_subject"
  case validFrom = "certificate_valid_from"
  case validUntil = "certificate_valid_until"
  case issuingCountry = "issuing_country"
  case valid = "validity_info"
}

