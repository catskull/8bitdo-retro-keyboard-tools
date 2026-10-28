// Drive the 8BitDo Retro Keyboard's lock LEDs from the host via standard HID LED usages.
// Usage: leds [blink|on|off] [num|caps|scroll]   (default: blink scroll)
import Foundation
import IOKit.hid

setvbuf(stdout, nil, _IOLBF, 0)
let args = Array(CommandLine.arguments.dropFirst())
let action = args.first ?? "blink"
let which = args.count > 1 ? args[1] : "scroll"
let ledUsage = ["num": kHIDUsage_LED_NumLock, "caps": kHIDUsage_LED_CapsLock, "scroll": kHIDUsage_LED_ScrollLock][which] ?? kHIDUsage_LED_ScrollLock

let mgr = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
IOHIDManagerSetDeviceMatching(mgr, [kIOHIDVendorIDKey: 0x2DC8, kIOHIDProductIDKey: 0x5200,
                                    kIOHIDPrimaryUsagePageKey: kHIDPage_GenericDesktop, kIOHIDPrimaryUsageKey: kHIDUsage_GD_Keyboard] as CFDictionary)
IOHIDManagerOpen(mgr, IOOptionBits(kIOHIDOptionsTypeNone))
guard let dev = (IOHIDManagerCopyDevices(mgr) as? Set<IOHIDDevice>)?.first else { print("keyboard interface not found"); exit(1) }

let r = IOHIDDeviceOpen(dev, IOOptionBits(kIOHIDOptionsTypeNone))
guard r == kIOReturnSuccess else {
    print(String(format: "IOHIDDeviceOpen failed: 0x%08x (macOS may require Input Monitoring permission for the terminal)", r)); exit(1)
}
let match = [kIOHIDElementUsagePageKey: kHIDPage_LEDs, kIOHIDElementUsageKey: ledUsage] as CFDictionary
guard let el = (IOHIDDeviceCopyMatchingElements(dev, match, IOOptionBits(kIOHIDOptionsTypeNone)) as? [IOHIDElement])?.first
else { print("LED element not found in the keyboard's HID descriptor"); exit(1) }

func set(_ on: Bool) {
    let v = IOHIDValueCreateWithIntegerValue(kCFAllocatorDefault, el, mach_absolute_time(), on ? 1 : 0)
    let s = IOHIDDeviceSetValue(dev, el, v)
    if s != kIOReturnSuccess { print(String(format: "SetValue failed: 0x%08x", s)) }
}

switch action {
case "on": set(true)
case "off": set(false)
default:
    print("blinking \(which) lock LED...")
    for _ in 0..<6 { set(true); Thread.sleep(forTimeInterval: 0.4); set(false); Thread.sleep(forTimeInterval: 0.4) }
}
