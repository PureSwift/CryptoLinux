//
//  CryptoLinux.swift
//
//
//  Created by Alsey Coleman Miller on 5/6/22.
//

import Foundation
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
    
    public static var path: String { "/proc/crypto" }
    
    internal let ciphers: [Cipher]
    
    // MARK: - Initializaton
    
    public init() throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: Self.path), options: [.mappedIfSafe])
        guard let string = String(data: data, encoding: .utf8) else {
            throw CocoaError(.fileReadCorruptFile)
        }
        self.init(string)
    }
    
    internal init(_ driverList: String) {
        // parse ciphers
        self.init([])
    }
    
    internal init(_ ciphers: [Cipher]) {
        self.ciphers = ciphers
    }
    
    // MARK: - Methods
    
    
}
