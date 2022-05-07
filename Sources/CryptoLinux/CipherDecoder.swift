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
            referencing: .string(Substring(string)),
            userInfo: userInfo,
            log: log
        )
        // decode from container
        return try [T].init(from: decoder)
    }
    
    static func decode(_ string: String) throws -> [[String: Substring]] {
        let lines = string.split(separator: "\n")
        let entries = lines
            .filter { $0.isEmpty }
            .count + 1
        var result = [[String: Substring]]()
        result.reserveCapacity(entries)
        result.append([:])
        var entryIndex = 0
        for (lineIndex, line) in lines.enumerated() {
            if line.isEmpty {
                result.append([:])
                entryIndex += 1
            } else {
                // parse key-value pair
                let entryLines = line.split(separator: ":")
                guard entryLines.count == 2 else {
                    throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: [], debugDescription: "Invalid key-value pair at line \(lineIndex)"))
                }
                let key = entryLines[0].replacingOccurrences(of: " ", with: "")
                let value = entryLines[1]
                result[entryIndex][key] = value
            }
        }
        return result
    }
}

// MARK: - Decoder

internal extension CipherDecoder {
    
    final class Decoder: Swift.Decoder {
        
        /// The path of coding keys taken to get to this point in decoding.
        fileprivate(set) var codingPath: [CodingKey]
        
        /// Any contextual information set by the user for decoding.
        let userInfo: [CodingUserInfoKey : Any]
        
        let log: ((String) -> ())?
        
        let container: [[String: Substring]]
        
        // MARK: - Initialization
        
        fileprivate init(referencing container: [[String: Substring]],
                         at codingPath: [CodingKey] = [],
                         userInfo: [CodingUserInfoKey : Any],
                         log: ((String) -> ())?) {
            
            self.container = container
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
            let container = self.stack.top
            switch container {
            case let .strings(strings):
                return CipherUnkeyedDecodingContainer(referencing: self, wrapping: strings)
            case let .string(string):
                // try to forceably parse string
                let strings = try decodeUnkeyedContainer(string)
                self.stack.pop() // replace stack
                self.stack.push(.strings(strings))
                return CipherUnkeyedDecodingContainer(referencing: self, wrapping: strings)
            }
        }
        
        func singleValueContainer() throws -> SingleValueDecodingContainer {
            log?("Requested single value container for path \"\(codingPath.path)\"")
            fatalError()
        }
    }
}

// MARK: - Unboxing Values

internal extension CipherDecoder.Decoder {
    
    func unbox <T: CipherRawDecodable> (_ string: Substring, as type: T.Type) throws -> T {
        guard let value = T.init(cipher: string) else {
            throw DecodingError.typeMismatch(type, DecodingError.Context(codingPath: self.codingPath, debugDescription: "Could not parse \(type) from \(string)"))
        }
        return value
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

// MARK: - KeyedDecodingContainer

internal struct CipherKeyedDecodingContainer <K: CodingKey> : KeyedDecodingContainerProtocol {
    
    typealias Key = K
    
    // MARK: Properties
    
    /// A reference to the encoder we're reading from.
    let decoder: CipherDecoder.Decoder
    
    /// A reference to the container we're reading from.
    let container: [Substring]
    
    /// The path of coding keys taken to get to this point in decoding.
    let codingPath: [CodingKey]
    
    /// All the keys the Decoder has for this container.
    let allKeys: [Key]
    
    // MARK: Initialization
    
    /// Initializes `self` by referencing the given decoder and container.
    init(referencing decoder: CipherDecoder.Decoder, wrapping container: [Substring]) {
        
        self.decoder = decoder
        self.container = container
        self.codingPath = decoder.codingPath
        self.allKeys = container.compactMap { Key(intValue: Int($0.type.rawValue)) }
    }
    
    // MARK: KeyedDecodingContainerProtocol
    
    func contains(_ key: Key) -> Bool {
        
        self.decoder.log?("Check whether key \"\(key.stringValue)\" exists")
        guard let typeCode = try? self.decoder.typeCode(for: key)
            else { return false }
        return container.contains { $0.type == typeCode }
    }
    
    func decodeNil(forKey key: Key) throws -> Bool {
        
        // set coding key context
        self.decoder.codingPath.append(key)
        defer { self.decoder.codingPath.removeLast() }
        
        self.decoder.log?("Check if nil at path \"\(decoder.codingPath.path)\"")
        
        // check if key exists since there is no way to represent nil in Cipher
        // empty data and strings should not be falsely reported as nil
        return try self.value(for: key) == nil
    }
    
    func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool {
        
        return try decodeCipher(type, forKey: key)
    }
    
    func decode(_ type: Int.Type, forKey key: Key) throws -> Int {
        
        let value = try decodeNumeric(Int32.self, forKey: key)
        return Int(value)
    }
    
    func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 {
        
        return try decodeCipher(type, forKey: key)
    }
    
    func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 {
        
        return try decodeNumeric(type, forKey: key)
    }
    
    func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 {
        
        return try decodeNumeric(type, forKey: key)
    }
    
    func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 {
        
        return try decodeNumeric(type, forKey: key)
    }
    
    func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt {
        
        let value = try decodeNumeric(UInt32.self, forKey: key)
        return UInt(value)
    }
    
    func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 {
        
        return try decodeCipher(type, forKey: key)
    }
    
    func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 {
        
        return try decodeNumeric(type, forKey: key)
    }
    
    func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 {
        
        return try decodeNumeric(type, forKey: key)
    }
    
    func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 {
        
        return try decodeNumeric(type, forKey: key)
    }
    
    func decode(_ type: Float.Type, forKey key: Key) throws -> Float {
        
        let bitPattern = try decodeNumeric(UInt32.self, forKey: key)
        return Float(bitPattern: bitPattern)
    }
    
    func decode(_ type: Double.Type, forKey key: Key) throws -> Double {
        
        let bitPattern = try decodeNumeric(UInt64.self, forKey: key)
        return Double(bitPattern: bitPattern)
    }
    
    func decode(_ type: String.Type, forKey key: Key) throws -> String {
        
        return try decodeCipher(type, forKey: key)
    }
    
    func decode <T: Decodable> (_ type: T.Type, forKey key: Key) throws -> T {
        
        return try self.value(for: key, type: type) { try decoder.unboxDecodable($0, as: type) }
    }
    
    func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> where NestedKey : CodingKey {
        
        fatalError()
    }
    
    func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
        
        fatalError()
    }
    
    func superDecoder() throws -> Decoder {
        
        fatalError()
    }
    
    func superDecoder(forKey key: Key) throws -> Decoder {
        
        fatalError()
    }
    
    // MARK: Private Methods
    
    /// Decode native value type from Cipher data.
    private func decodeCipher <T: CipherRawDecodable> (_ type: T.Type, forKey key: Key) throws -> T {
        
        return try self.value(for: key, type: type) { try decoder.unbox($0.value, as: type) }
    }
    
    private func decodeNumeric <T: CipherRawDecodable & FixedWidthInteger> (_ type: T.Type, forKey key: Key) throws -> T {
        
        return try self.value(for: key, type: type) { try decoder.unboxNumeric($0.value, as: type) }
    }
    
    /// Access actual value
    @inline(__always)
    private func value <T> (for key: Key, type: T.Type, decode: (Substring) throws -> T) throws -> T {
        
        self.decoder.codingPath.append(key)
        defer { self.decoder.codingPath.removeLast() }
        decoder.log?("Will read value at path \"\(decoder.codingPath.path)\"")
        guard let item = try self.value(for: key) else {
            throw DecodingError.valueNotFound(type, DecodingError.Context(codingPath: self.decoder.codingPath, debugDescription: "Expected \(type) value but found null instead."))
        }
        return try decode(item)
    }
    
    /// Access actual value
    private func value(for key: Key) throws -> Substring? {
        let typeCode = try self.decoder.typeCode(for: key)
        return container.first { $0.type == typeCode }
    }
}

// MARK: - SingleValueDecodingContainer

internal struct CipherSingleValueDecodingContainer: SingleValueDecodingContainer {
    
    // MARK: Properties
    
    /// A reference to the decoder we're reading from.
    let decoder: CipherDecoder.Decoder
    
    /// A reference to the container we're reading from.
    let container: Substring
    
    /// The path of coding keys taken to get to this point in decoding.
    let codingPath: [CodingKey]
    
    // MARK: Initialization
    
    /// Initializes `self` by referencing the given decoder and container.
    init(referencing decoder: CipherDecoder.Decoder, wrapping container: Substring) {
        
        self.decoder = decoder
        self.container = container
        self.codingPath = decoder.codingPath
    }
    
    // MARK: SingleValueDecodingContainer
    
    func decodeNil() -> Bool {
        
        return container.value.isEmpty
    }
    
    func decode(_ type: Bool.Type) throws -> Bool {
        
        return try self.decoder.unbox(container.value, as: type)
    }
    
    func decode(_ type: Int.Type) throws -> Int {
        
        let value = try self.decoder.unboxNumeric(container.value, as: Int32.self)
        return Int(value)
    }
    
    func decode(_ type: Int8.Type) throws -> Int8 {
        
        return try self.decoder.unbox(container.value, as: type)
    }
    
    func decode(_ type: Int16.Type) throws -> Int16 {
        
        return try self.decoder.unboxNumeric(container.value, as: type)
    }
    
    func decode(_ type: Int32.Type) throws -> Int32 {
        
        return try self.decoder.unboxNumeric(container.value, as: type)
    }
    
    func decode(_ type: Int64.Type) throws -> Int64 {
        
        return try self.decoder.unboxNumeric(container.value, as: type)
    }
    
    func decode(_ type: UInt.Type) throws -> UInt {
        
        let value = try self.decoder.unboxNumeric(container.value, as: UInt32.self)
        return UInt(value)
    }
    
    func decode(_ type: UInt8.Type) throws -> UInt8 {
        
        return try self.decoder.unbox(container.value, as: type)
    }
    
    func decode(_ type: UInt16.Type) throws -> UInt16 {
        
        return try self.decoder.unboxNumeric(container.value, as: type)
    }
    
    func decode(_ type: UInt32.Type) throws -> UInt32 {
        
        return try self.decoder.unboxNumeric(container.value, as: type)
    }
    
    func decode(_ type: UInt64.Type) throws -> UInt64 {
        
        return try self.decoder.unboxNumeric(container.value, as: type)
    }
    
    func decode(_ type: Float.Type) throws -> Float {
        
        let value = try self.decoder.unboxNumeric(container.value, as: UInt32.self)
        return Float(bitPattern: value)
    }
    
    func decode(_ type: Double.Type) throws -> Double {
        
        let value = try self.decoder.unboxNumeric(container.value, as: UInt64.self)
        return Double(bitPattern: value)
    }
    
    func decode(_ type: String.Type) throws -> String {
        
        return try self.decoder.unbox(container.value, as: type)
    }
    
    func decode <T : Decodable> (_ type: T.Type) throws -> T {
        
        return try self.decoder.unboxDecodable(container, as: type)
    }
}

// MARK: UnkeyedDecodingContainer

internal struct CipherUnkeyedDecodingContainer: UnkeyedDecodingContainer {
    
    // MARK: Properties
    
    /// A reference to the encoder we're reading from.
    let decoder: CipherDecoder.Decoder
    
    /// A reference to the container we're reading from.
    let container: [Substring]
    
    /// The path of coding keys taken to get to this point in decoding.
    let codingPath: [CodingKey]
    
    private(set) var currentIndex: Int = 0
    
    // MARK: Initialization
    
    /// Initializes `self` by referencing the given decoder and container.
    init(referencing decoder: CipherDecoder.Decoder, wrapping container: [Substring]) {
        
        self.decoder = decoder
        self.container = container
        self.codingPath = decoder.codingPath
    }
    
    // MARK: UnkeyedDecodingContainer
    
    var count: Int? {
        return _count
    }
    
    private var _count: Int {
        return container.count
    }
    
    var isAtEnd: Bool {
        return currentIndex >= _count
    }
    
    mutating func decodeNil() throws -> Bool {
        
        try assertNotEnd()
        
        // never optional, decode
        return false
    }
    
    mutating func decode(_ type: Bool.Type) throws -> Bool { fatalError("stub") }
    mutating func decode(_ type: Int.Type) throws -> Int { fatalError("stub") }
    mutating func decode(_ type: Int8.Type) throws -> Int8 { fatalError("stub") }
    mutating func decode(_ type: Int16.Type) throws -> Int16 { fatalError("stub") }
    mutating func decode(_ type: Int32.Type) throws -> Int32 { fatalError("stub") }
    mutating func decode(_ type: Int64.Type) throws -> Int64 { fatalError("stub") }
    mutating func decode(_ type: UInt.Type) throws -> UInt { fatalError("stub") }
    mutating func decode(_ type: UInt8.Type) throws -> UInt8 { fatalError("stub") }
    mutating func decode(_ type: UInt16.Type) throws -> UInt16 { fatalError("stub") }
    mutating func decode(_ type: UInt32.Type) throws -> UInt32 { fatalError("stub") }
    mutating func decode(_ type: UInt64.Type) throws -> UInt64 { fatalError("stub") }
    mutating func decode(_ type: Float.Type) throws -> Float { fatalError("stub") }
    mutating func decode(_ type: Double.Type) throws -> Double { fatalError("stub") }
    mutating func decode(_ type: String.Type) throws -> String { fatalError("stub") }
    
    mutating func decode <T : Decodable> (_ type: T.Type) throws -> T {
        
        try assertNotEnd()
        
        self.decoder.codingPath.append(Index(intValue: self.currentIndex))
        defer { self.decoder.codingPath.removeLast() }
        
        let item = self.container[self.currentIndex]
        
        let decoded = try self.decoder.unboxDecodable(item, as: type)
        
        self.currentIndex += 1
        
        return decoded
    }
    
    mutating func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey : CodingKey {
        
        throw DecodingError.typeMismatch(type, DecodingError.Context(codingPath: codingPath, debugDescription: "Cannot decode \(type)"))
    }
    
    mutating func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
        
        throw DecodingError.typeMismatch([Any].self, DecodingError.Context(codingPath: codingPath, debugDescription: "Cannot decode unkeyed container."))
    }
    
    mutating func superDecoder() throws -> Decoder {
        
        // set coding key context
        self.decoder.codingPath.append(Index(intValue: currentIndex))
        defer { self.decoder.codingPath.removeLast() }
        
        // log
        self.decoder.log?("Requested super decoder for path \"\(self.decoder.codingPath.path)\"")
        
        // check for end of array
        try assertNotEnd()
        
        // get item
        let item = container[currentIndex]
        
        // increment counter
        self.currentIndex += 1
        
        // create new decoder
        let decoder = CipherDecoder.Decoder(referencing: .item(item),
                                         at: self.decoder.codingPath,
                                         userInfo: self.decoder.userInfo,
                                         log: self.decoder.log,
                                         options: self.decoder.options)
        
        return decoder
    }
    
    // MARK: Private Methods
    
    @inline(__always)
    private func assertNotEnd() throws {
        
        guard isAtEnd == false else {
            
            throw DecodingError.valueNotFound(Any?.self, DecodingError.Context(codingPath: self.decoder.codingPath + [Index(intValue: self.currentIndex)], debugDescription: "Unkeyed container is at end."))
        }
    }
}

internal extension CipherUnkeyedDecodingContainer {
    
    struct Index: CodingKey {
        
        public let index: Int
        
        public init(intValue: Int) {
            self.index = intValue
        }
        
        public init?(stringValue: String) {
            return nil
        }
        
        public var intValue: Int? {
            return index
        }
        
        public var stringValue: String {
            return "\(index)"
        }
    }
}

// MARK: - Decodable Types

internal protocol CipherRawDecodable {
    
    init?(cipher string: Substring)
}

extension String: CipherRawDecodable {
    
    init?(cipher string: Substring) {
        self.init(string)
    }
}

extension Bool: CipherRawDecodable {
    
    init?(cipher string: Substring) {
        switch string {
        case "yes":
            self = true
        case "no":
            self = false
        default:
            return nil
        }
    }
}
