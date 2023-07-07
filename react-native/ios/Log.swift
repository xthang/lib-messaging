//
//  Created by Thang Nguyen on 10/12/22.
//

import Foundation
import os

public struct Log {
	
	@available(iOS 14.0, macOS 11.0, *)
	struct Compatible {
		static let logger = Logger() // Logger(subsystem: Bundle.main.bundleIdentifier!, category: "")
	}
	
	public enum `Type` { case M, P, I, D, W, E }
	
	private static func print_(level: OSLogType, _ tag: String, _ arguments: [Any?]) {
		let msg = arguments.map { "\($0 ?? "--")" }.joined(separator: " ")
		if #available(iOS 14.0, macOS 11.0, *) {
			Compatible.logger.log(level: level, "[\(tag)] \(msg)")
		} else {
			NSLog("[\(tag)] \(msg)")
		}
	}
	
	public static func log(_ tag: String, type: `Type`, _ arguments: Any?...) {
		switch type {
		case .M: m(tag, arguments)
		case .P: p(tag, arguments)
		case .I: i(tag, arguments)
		case .D: d(tag, arguments)
		case .W: w(tag, arguments)
		case .E: e(tag, arguments)
		}
	}
	
	public static func m(_ tag: String, _ arguments: Any?...) {
		print_(level: .default, tag, arguments)
	}
	
	public static func i(_ tag: String, _ arguments: Any?...) {
		print_(level: .info, tag, arguments)
	}
	
	public static func d(_ tag: String, _ arguments: Any?...) {
		print_(level: .debug, tag, arguments)
	}
	
	public static func w(_ tag: String, _ arguments: Any?...) {
		let msg = arguments.compactMap { "\($0 ?? "--")" }.joined(separator: " ")
		if #available(iOS 14.0, macOS 11.0, *) {
			Compatible.logger.warning("[\(tag)] \(msg)")
		} else {
			NSLog("[\(tag)] \(msg)")
		}
	}
	
	public static func e(_ tag: String, _ arguments: Any?...) {
		print_(level: .error, tag, arguments)
	}
	
	public static func p(_ tag: String, _ arguments: Any?...) {
		let msg = arguments.compactMap { "\($0 ?? "--")" }.joined(separator: " ")
		print("\(tag) | \(msg)")
	}
}
