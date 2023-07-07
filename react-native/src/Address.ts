//
// Copyright 2023 Ready.io
//

/* eslint-disable lines-between-class-members */

// import * as Native from './Native'

// export class ProtocolAddress {
//   readonly _nativeHandle: Native.ProtocolAddress

//   private constructor(handle: Native.ProtocolAddress) {
//     this._nativeHandle = handle
//   }

//   static _fromNativeHandle(handle: Native.ProtocolAddress): ProtocolAddress {
//     return new ProtocolAddress(handle)
//   }

//   static new(name: string, deviceId: number): ProtocolAddress {
//     return new ProtocolAddress(Native.ProtocolAddress_New(name, deviceId))
//   }

//   name(): string {
//     return Native.ProtocolAddress_Name(this)
//   }

//   deviceId(): number {
//     return Native.ProtocolAddress_DeviceId(this)
//   }
// }

export class ProtocolAddress {
  static fromString(s: string): ProtocolAddress {
    if (!s.match(/.*\.\d+/)) {
      throw new Error(`Invalid ProtocolAddress string: ${s}`)
    }
    const parts = s.split('.')
    return new ProtocolAddress(parts[0]!, parseInt(parts[1]!))
  }

  private _name: string
  private _deviceId: number

  constructor(_name: string, _deviceId: number) {
    this._name = _name
    this._deviceId = _deviceId
  }

  // Readonly properties
  get name(): string {
    return this._name
  }

  get deviceId(): number {
    return this._deviceId
  }

  // Expose properties as fuynctions for compatibility
  getName(): string {
    return this._name
  }

  getDeviceId(): number {
    return this._deviceId
  }

  toString(): string {
    return `${this._name}.${this._deviceId}`
  }

  equals(other: ProtocolAddress): boolean {
    return other.name === this._name && other.deviceId === this._deviceId
  }
}
