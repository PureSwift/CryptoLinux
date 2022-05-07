//
//  SocketDescriptor.swift
//  
//
//  Created by Alsey Coleman Miller on 5/7/22.
//

import Socket

internal extension SocketDescriptor {
    
    /**
     Opens a Linux Crypto API socket.
     
     To initialize the socket interface, the following sequence has to be performed by the consumer:

     Create a socket of type `AF_ALG` with the `struct sockaddr_alg` parameter specified below for the different cipher types.
     Invoke bind with the socket descriptor
     Invoke accept with the socket descriptor. The `accept` system call returns a new file descriptor that is to be used to interact with the particular cipher instance. When invoking send/write or recv/read system calls to send data to the kernel or obtain data from the kernel, the file descriptor returned by accept must be used.
     */
    static func crypto(type: CipherType, name: Cipher.Name) throws -> SocketDescriptor {
        let address = CryptoSocketAddress(name: name, type: type)
        let fileDescriptor = try SocketDescriptor(CryptoSocketProtocol.default)
        return try fileDescriptor.closeIfThrows {
            try fileDescriptor.bind(address)
            return try fileDescriptor.accept()
        }
    }
}
