//
//  CipherDecoder.swift
//  
//
//  Created by Alsey Coleman Miller on 5/6/22.
//

import Foundation

/// Decodes ciphers from string list.
internal struct CipherDecoder {
    
    // MARK: - Properties
    
    public var log: ((String) -> ())?
    
    /// Any contextual information set by the user for encoding.
    public var userInfo = [CodingUserInfoKey : Any]()
    
    // MARK: - Initialization
    
    public init() { }
    
    // MARK: - Methods
    
    public func decode(_ data: Data) throws -> [Cipher] {
        guard let string = String(data: data, encoding: .utf8) else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: [], debugDescription: "Data cannot be parsed as UTF8 string."))
        }
        return try decode(string)
    }
    
    func decode(_ string: String) throws -> [Cipher] {
        return try decode(Cipher.self, from: string)
    }
    
    func decode<T: Decodable>(_ type: T.Type, from string: String) throws -> [T] {
        log?("Will decode \(String(reflecting: T.self))")
        // initialize decoder
        let decoder = Decoder(
            referencing: string,
            userInfo: userInfo,
            log: log
        )
        // decode from container
        return try [T].init(from: decoder)
    }
}

// MARK: - Decoder

internal extension CipherDecoder {
    
    struct Decoder: Swift.Decoder {
        
        /// The path of coding keys taken to get to this point in decoding.
        fileprivate(set) var codingPath: [CodingKey]
        
        /// Any contextual information set by the user for decoding.
        let userInfo: [CodingUserInfoKey : Any]
        
        let log: ((String) -> ())?
        
        let string: String
        
        // MARK: - Initialization
        
        fileprivate init(referencing string: String,
                         at codingPath: [CodingKey] = [],
                         userInfo: [CodingUserInfoKey : Any],
                         log: ((String) -> ())?) {
            
            self.string = string
            self.codingPath = codingPath
            self.userInfo = userInfo
            self.log = log
        }
        
        // MARK: - Methods
        
        func container <Key: CodingKey> (keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> {
            log?("Requested container keyed by \(type.sanitizedName) for path \"\(codingPath.path)\"")
            fatalError()
        }
        
        func unkeyedContainer() throws -> UnkeyedDecodingContainer {
            log?("Requested unkeyed container for path \"\(codingPath.path)\"")
            fatalError()
        }
        
        func singleValueContainer() throws -> SingleValueDecodingContainer {
            log?("Requested single value container for path \"\(codingPath.path)\"")
            fatalError()
        }
    }
}

// MARK: - Stack

internal extension CipherDecoder {
    
    struct Stack {
        
        private(set) var containers = [Container]()
        
        fileprivate init(_ container: Container) {
            self.containers = [container]
        }
        
        var top: Container {
            guard let container = containers.last
                else { fatalError("Empty container stack.") }
            return container
        }
        
        mutating func push(_ container: Container) {
            containers.append(container)
        }
        
        @discardableResult
        mutating func pop() -> Container {
            guard let container = containers.popLast()
                else { fatalError("Empty container stack.") }
            return container
        }
    }
}

internal extension CipherDecoder.Stack {
    
    enum Container {
        
        case strings([Substring])
        case string(Substring)
    }
}
