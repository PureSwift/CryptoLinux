// swift-tools-version: 5.6
import PackageDescription
import class Foundation.ProcessInfo

// force building as dynamic library
let dynamicLibrary = ProcessInfo.processInfo.environment["SWIFT_BUILD_DYNAMIC_LIBRARY"] != nil
let libraryType: PackageDescription.Product.Library.LibraryType? = dynamicLibrary ? .dynamic : nil

var package = Package(
    name: "CryptoLinux",
    products: [
        .library(
            name: "CryptoLinux",
            type: libraryType,
            targets: ["CryptoLinux"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/PureSwift/Socket.git",
            branch: "main"
        )
    ],
    targets: [
        .target(
            name: "CryptoLinux",
            dependencies: []
        ),
        .testTarget(
            name: "CryptoLinuxTests",
            dependencies: ["CryptoLinux"]
        ),
    ]
)

let buildDocs = ProcessInfo.processInfo.environment["BUILDING_FOR_DOCUMENTATION_GENERATION"] != nil
if buildDocs {
    package.dependencies += [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
    ]
}
