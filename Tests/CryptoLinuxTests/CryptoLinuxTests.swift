import XCTest
@testable import CryptoLinux

final class CryptoLinuxTests: XCTestCase {
    
    #if os(Linux)
    func testLoadDrivers() throws {
        let crypto = try CryptoLinux()
        XCTAssert(crypto.count > 1, "\(crypto.count)")
    }
    #endif
    
    func testArm64CipherParsing() throws {
        let crypto = try CryptoLinux(TestCipherList.arm64, log: { print("Decoder:", $0) })
        XCTAssert(crypto.count > 1, "\(crypto.count)")
        XCTAssertEqual(crypto.first?.name, "__ecb(aes)")
        XCTAssertEqual(crypto.first?.driver, "cryptd(__ecb-aes-ce)")
        XCTAssertEqual(crypto.first?.module, "cryptd")
        XCTAssertEqual(crypto.first?.priority, 350)
        XCTAssertEqual(crypto.first?.referenceCount, 2)
        XCTAssertEqual(crypto.first?.selfTest, "passed")
        XCTAssertEqual(crypto.first?.isInternal, true)
        XCTAssertEqual(crypto.first?.async, true)
        XCTAssertEqual(crypto.first?.blockSize, 16)
        XCTAssertEqual(crypto.first?.minKeysize, 16)
        XCTAssertEqual(crypto.first?.maxKeysize, 32)
        XCTAssertEqual(crypto.first?.ivSize, 0)
        XCTAssertEqual(crypto.first?.chunkSize, 16)
        XCTAssertEqual(crypto.first?.walkSize, 16)
    }
    
    func testAllwinnerH616CipherParsing() throws {
        let crypto = try CryptoLinux(TestCipherList.allwinnerH616, log: { print("Decoder:", $0) })
        XCTAssert(crypto.isEmpty == false)
    }
    
    func testCipherDecoder() throws {
        var decoder = CipherDecoder()
        decoder.log = { print("Decoder:", $0) }
        let value = try decoder.decode([String: String].self, from: TestCipherList.arm64)
        XCTAssertEqual(value.count, 90)
    }
}
