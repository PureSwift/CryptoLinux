//
//  CipherName.swift
//  
//
//  Created by Alsey Coleman Miller on 5/6/22.
//

/// Linux Crypto Cipher Name
public struct CipherName: RawRepresentable, Equatable, Hashable, Codable {
    
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue
    }
}

// MARK: - ExpressibleByStringLiteral

extension CipherName: ExpressibleByStringLiteral {
    
    public init(stringLiteral value: String) {
        self.init(rawValue: value)
    }
}

// MARK: - CustomStringConvertible

extension CipherName: CustomStringConvertible, CustomDebugStringConvertible {
    
    public var description: String {
        rawValue
    }
    
    public var debugDescription: String {
        description
    }
}

// MARK: - Definitions

public extension CipherName {
    
    @_alwaysEmitIntoClient
    static var sha1: CipherName { "sha1" }
    
    @_alwaysEmitIntoClient
    static var sha256: CipherName { "sha256" }
    
    @_alwaysEmitIntoClient
    static var sha224: CipherName { "sha224" }
    
    @_alwaysEmitIntoClient
    static var sha384: CipherName { "sha384" }
    
    @_alwaysEmitIntoClient
    static var sha512: CipherName { "sha512" }
    
    @_alwaysEmitIntoClient
    static var sha3_224: CipherName { "sha3-224" }
    
    @_alwaysEmitIntoClient
    static var sha3_256: CipherName { "sha3-256" }
    
    @_alwaysEmitIntoClient
    static var sha3_384: CipherName { "sha3-384" }
    
    @_alwaysEmitIntoClient
    static var sha3_512: CipherName { "sha3-512" }
}
