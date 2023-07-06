// swift-tools-version:5.0

//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import PackageDescription

let rustBuildDir = "../target/debug/"

let package = Package(
    name: "LibMessagingClient",
    products: [
        .library(
            name: "LibMessagingClient",
            targets: ["LibMessagingClient"]
        )
    ],
    dependencies: [],
    targets: [
        .systemLibrary(name: "MessagingFfi"),
        .target(
            name: "LibMessagingClient",
            dependencies: ["MessagingFfi"],
            exclude: ["Logging.m"]
        ),
        .testTarget(
            name: "LibMessagingClientTests",
            dependencies: ["LibMessagingClient"],
            linkerSettings: [.unsafeFlags(["-L\(rustBuildDir)"])]
        )
    ]
)
