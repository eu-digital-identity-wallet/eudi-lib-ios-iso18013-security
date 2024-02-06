//
//  File.swift
//  
//
//  Created by ffeli on 22/11/2022.
/*
TBSCertList  ::=  SEQUENCE  {
*     version                 Version OPTIONAL,
*                             -- if present, must be v2
*     signature               AlgorithmIdentifier,
*     issuer                  Name,
*     thisUpdate              ChoiceOfTime,
*     nextUpdate              ChoiceOfTime OPTIONAL,
*     revokedCertificates     SEQUENCE OF SEQUENCE  {
*         userCertificate         CertificateSerialNumber,
*         revocationDate          ChoiceOfTime,
*         crlEntryExtensions      Extensions OPTIONAL
*                                 -- if present, must be v2
*         }  OPTIONAL,
*     crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
*                                  -- if present, must be v2
*     }
* </pre>*/
import Foundation
import ASN1Decoder

public class X509CRL: CustomStringConvertible {
    private let asn1: [ASN1Object]
    private let block1: ASN1Object

    private static let beginPemBlock = "-----BEGIN X509 CRL-----"
    private static let endPemBlock   = "-----END X509 CRL-----"

    public convenience init(data: Data) throws {
        if String(data: data, encoding: .utf8)?.contains(X509CRL.beginPemBlock) ?? false {
            try self.init(pem: data)
        } else {
            try self.init(der: data)
        }
    }

    public init(der: Data) throws {
        asn1 = try ASN1DERDecoder.decode(data: der)
        guard asn1.count > 0,
            let block1 = asn1.first?.sub(0) else {
                throw X509CRLError.parseError
        }

        self.block1 = block1
    }

    public convenience init(pem: Data) throws {
        guard let derData = X509CRL.decodeToDER(pem: pem) else {
            throw X509CRLError.parseError
        }

        try self.init(der: derData)
    }

    init(asn1: ASN1Object) throws {
        guard let block1 = asn1.sub(0) else { throw X509CRLError.parseError }

        self.asn1 = [asn1]
        self.block1 = block1
    }

    public var description: String {
        return asn1.reduce("") { $0 + "\($1.description)\n" }
    }

    // read possibile PEM encoding
    private static func decodeToDER(pem pemData: Data) -> Data? {
        if
            let pem = String(data: pemData, encoding: .ascii),
            pem.contains(beginPemBlock) {

            let lines = pem.components(separatedBy: .newlines)
            var base64buffer  = ""
            var certLine = false
            for line in lines {
                if line == endPemBlock {
                    certLine = false
                }
                if certLine {
                    base64buffer.append(line)
                }
                if line == beginPemBlock {
                    certLine = true
                }
            }
            if let derDataDecoded = Data(base64Encoded: base64buffer) {
                return derDataDecoded
            }
        }

        return nil
    }
  
  
  public var badBlocks: [ASN1Object]? {
    guard let s5 = block1.sub(5) else { return nil}
    return (0..<s5.subCount()).compactMap { s5.sub($0) }
  }
  
  public var badSerials: [Data]? { badBlocks?.compactMap { $0.sub(0)?.value as? Data } }
  
  public var badDates: [Date]? { badBlocks?.compactMap { $0.sub(1)?.value as? Date } }
  
  public var badSerialNumbers: [String]? { badSerials?.map { Self.dataToHexString($0) } }
  
  public static func dataToHexString(_ data: Data) -> String {
      return data.map { String(format: "%02X", $0) }.joined(separator: " ")
  }
}


public enum X509CRLError: Error {
    case parseError
    case outOfBuffer
}


