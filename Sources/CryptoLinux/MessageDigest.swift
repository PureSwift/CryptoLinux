//
//  MessageDigest.swift
//  
//
//  Created by Alsey Coleman Miller on 5/7/22.
//

import Foundation
import Socket

/// Linux Crypto Message Digest
///
/// - SeeAlso: [Linux Kernel Message Digest API](https://www.kernel.org/doc/html/v5.10/crypto/userspace-if.html#message-digest-api)
public final class MessageDigest {
    
    internal let fileDescriptor: SocketDescriptor
    
    public private(set) var didFinalize = false
    
    deinit {
        do { try fileDescriptor.close() }
        catch {
            assertionFailure("Unable to close socket. \(error.localizedDescription)")
        }
    }
    
    internal init(
        type: CipherType = "hash",
        name: Cipher.Name
    ) throws {
        self.fileDescriptor = try .crypto(type: type, name: name)
    }
    
    /// Incrementally updates the hash function with the contents of the buffer.
    ///
    /// Call this method one or more times to provide data to the hash function in blocks.
    /// After providing the last block of data, call the ``finalize()`` method to get the computed digest.
    /// Don’t call the update method again after finalizing the hash function.
    ///
    /// - Parameter bufferPointer: A pointer to the next block of data for the ongoing digest calculation.
    public func update(bufferPointer: UnsafeRawBufferPointer) throws {
        /**
         Using the send() system call, the application provides the data that should be processed with the message digest.
         The send system call allows the following flags to be specified:

         `MSG_MORE`: If this flag is set, the send system call acts like a message digest update function where the final hash is not yet calculated.
         If the flag is not set, the send system call calculates the final message digest immediately.
         */
        precondition(didFinalize == false)
        try send(bufferPointer, finalize: false)
    }
    
    /// Incrementally updates the hash function with the given data.
    ///
    /// Call this method one or more times to provide data to the hash function in blocks.
    /// After providing the last block of data, call the ``finalize()`` method to get the computed digest.
    /// Don’t call the update method again after finalizing the hash function.
    public func update<D>(data: D) throws where D : DataProtocol {
        try data.withContiguousStorageIfAvailable { bufferPointer in
            try update(bufferPointer: UnsafeRawBufferPointer(bufferPointer))
        }
    }
    
    /// Finalizes the hash function and returns the computed digest.
    ///
    /// Call this method after you provide the hash function with all the data to hash by making one or more
    /// calls to the ``update(data:)`` or ``update(bufferPointer:)`` method.
    /// After finalizing the hash function, discard it.
    public func finalize() throws -> Data {
        try send(.init(start: nil, count: 0), finalize: true)
        didFinalize = true
        // read response
        return try recieve()
    }
    
    internal func send(_ bufferPointer: UnsafeRawBufferPointer, finalize: Bool) throws {
        // send with specified flags
        let flags: MessageFlags = finalize ? [] : [.more]
        let _ = try fileDescriptor.send(bufferPointer, flags: flags)
        // set internal state
        if finalize {
            didFinalize = true
        } else {
            assert(didFinalize == false)
        }
    }
    
    internal func recieve() throws -> Data {
        let expectedLength = try fileDescriptor.receive(into: .init(start: nil, count: 0), flags: [.peek, .truncate], retryOnInterrupt: true)
        var data = Data(count: expectedLength)
        let bytesRead = try data.withUnsafeMutableBytes {
            try fileDescriptor.receive(into: $0)
        }
        assert(bytesRead == expectedLength)
        return data
    }
}
