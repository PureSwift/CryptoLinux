//
//  CryptoLinux.swift
//
//
//  Created by Alsey Coleman Miller on 5/6/22.
//

import SystemPackage
import Socket

/// Manages a socket to the [Linux Kernel Crypto API](https://www.kernel.org/doc/html/v5.10/crypto/userspace-if.html#)
///
/// The Linux kernel crypto API is accessible from user space. Currently, the following ciphers are accessible:
///
/// - Message digest including keyed message digest (HMAC, CMAC)
/// - Symmetric ciphers
/// - AEAD ciphers
/// - Random Number Generators
public struct CryptoLinux {
    
    // MARK: - Properties
    
    public static var path: FilePath { "/proc/crypto" }
    
    // MARK: - Initializaton
    
    public init() throws {
        let fileDescriptor = try FileDescriptor.open(Self.path, .readOnly)
        try fileDescriptor.closeAfter {
        }
    }
    
    internal init(_ driverList: String) {
        
    }
    
    // MARK: - Methods
    
    
}
