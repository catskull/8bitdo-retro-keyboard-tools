// Minimal client for the 8BitDo/Telink "dfu4" HID protocol (reverse-engineered from dfu4.exe).
// Usage: kbdfu list
//        kbdfu version|info|switch <location>
//        kbdfu flash <location> <firmware.dat> [--dry-run] [--model US|UK]
//   list    - enumerate receivers/bootloaders, send nothing
//   version - send 0x60 (what `dfu4 -r` does), read-only
//   info    - send 0x61 (first step of dfu4's update flow), read-only query
//   switch  - send 0x61 then 0x67 (switch to bootloader), then watch for the bootloader
//   flash   - full dfu4 sequence; --dry-run stops before 0x63 (start update), nothing is erased
import Foundation
import IOKit.hid

setvbuf(stdout, nil, _IOLBF, 0)
let vendorPage = 0x8C
let appIDs = [(0x2DC8, 0x5201), (0x2DC8, 0x5200)]  // receiver, keyboard
let bootIDs = [(0x2DC8, 0x5202), (0x248A, 0xFF08)]

func prop(_ d: IOHIDDevice, _ k: String) -> Int { (IOHIDDeviceGetProperty(d, k as CFString) as? Int) ?? -1 }
func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined(separator: " ") }
func fail(_ msg: String) -> Never { print("ERROR: \(msg)"); exit(1) }
func isBoot(_ d: IOHIDDevice) -> Bool { bootIDs.contains { $0.0 == prop(d, kIOHIDVendorIDKey) && $0.1 == prop(d, kIOHIDProductIDKey) } }

// Fresh enumeration each call so we see devices that re-enumerate (app <-> bootloader)
func hidDevices() -> [IOHIDDevice] {
    let mgr = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
    IOHIDManagerSetDeviceMatchingMultiple(mgr, (appIDs + bootIDs).map { [kIOHIDVendorIDKey: $0.0, kIOHIDProductIDKey: $0.1] } as CFArray)
    IOHIDManagerOpen(mgr, IOOptionBits(kIOHIDOptionsTypeNone))
    let devs = (IOHIDManagerCopyDevices(mgr) as? Set<IOHIDDevice>) ?? []
    return devs.sorted { prop($0, kIOHIDLocationIDKey) < prop($1, kIOHIDLocationIDKey) }
}
func vendorInterface(at loc: Int?, bootOnly: Bool = false) -> [IOHIDDevice] {
    hidDevices().filter { prop($0, kIOHIDPrimaryUsagePageKey) == vendorPage && (loc == nil || prop($0, kIOHIDLocationIDKey) == loc) && (!bootOnly || isBoot($0)) }
}

final class Receiver {
    let dev: IOHIDDevice
    var reply: [UInt8]? = nil
    var extra: [[UInt8]] = []
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
    static var seq: UInt8 = 1
    // The HID callback holds an unretained pointer to its Receiver, so keep every instance alive for the process lifetime
    static var all: [Receiver] = []
    static var lastSent: UInt8 = 0

    // Fails (nil) instead of exiting when the interface can't be opened, e.g. while it re-enumerates
    init?(_ d: IOHIDDevice) {
        dev = d
        // macOS delivers numbered reports with the report ID as the first byte of the buffer
        IOHIDDeviceRegisterInputReportCallback(dev, buf, 64, { ctx, _, _, _, _, rpt, len in
            let me = Unmanaged<Receiver>.fromOpaque(ctx!).takeUnretainedValue()
            let r = Array(UnsafeBufferPointer(start: rpt, count: len))
            if me.reply == nil { me.reply = r } else { me.extra.append(r) }
        }, Unmanaged.passUnretained(self).toOpaque())
        IOHIDDeviceScheduleWithRunLoop(dev, CFRunLoopGetCurrent(), CFRunLoopMode.defaultMode.rawValue)
        Receiver.all.append(self)
        let r = IOHIDDeviceOpen(dev, IOOptionBits(kIOHIDOptionsTypeNone))
        if r != kIOReturnSuccess { print(String(format: "   IOHIDDeviceOpen failed: 0x%08x", r)); return nil }
    }
    func close() {
        IOHIDDeviceRegisterInputReportCallback(dev, buf, 64, nil, nil)
        IOHIDDeviceUnscheduleFromRunLoop(dev, CFRunLoopGetCurrent(), CFRunLoopMode.defaultMode.rawValue)
        IOHIDDeviceClose(dev, IOOptionBits(kIOHIDOptionsTypeNone))
    }

    // Packet: B2 addr 55+subtype len+2 ~(len+2) seq data... sumLo sumHi, 33 bytes total
    func send(_ data: [UInt8], subtype: UInt8 = 0, quiet: Bool = false, timeout: Double = 1.0) -> [UInt8]? {
        var p = [UInt8](repeating: 0, count: 33)
        let n = UInt8(data.count + 2)
        p[0] = 0xB2; p[1] = 0xAA; p[2] = 0x55 &+ subtype; p[3] = n; p[4] = ~n; p[5] = Receiver.seq
        Receiver.lastSent = Receiver.seq
        for (i, b) in data.enumerated() { p[6 + i] = b }
        let sum = data.reduce(UInt16(0)) { $0 &+ UInt16($1) }
        p[6 + data.count] = UInt8(sum & 0xFF); p[7 + data.count] = UInt8(sum >> 8)
        Receiver.seq = Receiver.seq == 255 ? 1 : Receiver.seq + 1
        if !quiet { print("-> \(hex(p))") }
        reply = nil; extra = []
        let wr = IOHIDDeviceSetReport(dev, kIOHIDReportTypeOutput, 0xB2, p, p.count)
        if wr != kIOReturnSuccess { print(String(format: "   SetReport failed: 0x%08x", wr)); return nil }
        let deadline = Date().addingTimeInterval(timeout)
        while reply == nil && Date() < deadline { CFRunLoopRunInMode(.defaultMode, 0.01, true) }
        // Replies longer than one report (len byte > 0x19) continue in a second report; drain it
        if let r = reply, r.count > 3, r[3] > 0x19 {
            let d2 = Date().addingTimeInterval(timeout)
            while extra.isEmpty && Date() < d2 { CFRunLoopRunInMode(.defaultMode, 0.01, true) }
        }
        if !quiet { print(reply.map { "<- \(hex($0))" } ?? "<- (no reply within \(timeout)s)"); extra.forEach { print("<+ \(hex($0))") } }
        return reply
    }
}

func ack(_ r: [UInt8]?, _ cmd: UInt8) -> [UInt8]? {
    // Reply: B1 addr 55 len ~len devSeq type echoedSeq cmd status ...
    guard let r = r, r.count > 10, r[0] == 0xB1, r[6] == 0xA3 || r[6] == 0xA1, r[7] == Receiver.lastSent, r[8] == cmd else { return nil }
    return r
}

// dfu4's verify CRC: CRC-32 (0xEDB88320, init 0xFFFFFFFF) without the final inversion
func crcNoInv(_ d: [UInt8]) -> UInt32 {
    var c: UInt32 = 0xFFFFFFFF
    for b in d { c ^= UInt32(b); for _ in 0..<8 { c = (c & 1) != 0 ? (c >> 1) ^ 0xEDB88320 : c >> 1 } }
    return c
}

// 0x61 reply: app firmware has len > 9 and a nonzero "needs switch" byte; the bootloader replies short
func inBootloader(_ info: [UInt8]) -> Bool { !(info[3] > 9 && info[13] != 0) }

// The US (firmware_type 61) and UK (88) Retro Keyboards share 2dc8:5200 and the "TL 8BiDo" tag, so the only way to
// tell them apart is the version history 8BitDo has published for each (refresh from the catalog when new versions ship)
let keyboardVersions = ["US": ["1.4.6r", "1.7.2r", "1.7.7r"], "UK": ["1.3.6r"]]
func keyboardModel(_ ver: String) -> String? { keyboardVersions.first { $0.value.contains(ver) }?.key }

func waitFor(timeout: Double, _ pred: () -> IOHIDDevice?) -> IOHIDDevice? {
    let end = Date().addingTimeInterval(timeout)
    while Date() < end { if let d = pred() { return d }; Thread.sleep(forTimeInterval: 0.25) }
    return nil
}

let args = Array(CommandLine.arguments.dropFirst())
let mode = args.first ?? "list"
let loc = args.count > 1 ? Int(args[1].replacingOccurrences(of: "0x", with: ""), radix: 16) : nil

if mode == "list" {
    for d in hidDevices() {
        print(String(format: "  %04x:%04x  location 0x%08x  usagePage 0x%02x usage 0x%02x  fw %x%@", prop(d, kIOHIDVendorIDKey), prop(d, kIOHIDProductIDKey),
                     prop(d, kIOHIDLocationIDKey), prop(d, kIOHIDPrimaryUsagePageKey), prop(d, kIOHIDPrimaryUsageKey), prop(d, kIOHIDVersionNumberKey), isBoot(d) ? "  [bootloader]" : ""))
    }
    exit(0)
}
guard let loc = loc else { fail("pass the device's USB location, e.g. kbdfu \(mode) 0x02146400 (see `kbdfu list`)") }
let found = vendorInterface(at: loc)
guard found.count == 1, let first = found.first else { fail("no unique receiver vendor interface at location \(String(format: "0x%08x", loc))") }
print(String(format: "Using %04x:%04x at location 0x%08x%@", prop(first, kIOHIDVendorIDKey), prop(first, kIOHIDProductIDKey), loc, isBoot(first) ? " (bootloader)" : ""))

switch mode {
case "version": _ = Receiver(first)?.send([0x60])
case "info": _ = Receiver(first)?.send([0x61])
case "switch":
    guard let rx = Receiver(first) else { fail("cannot open device") }
    guard ack(rx.send([0x61]), 0x61) != nil else { fail("bad 0x61 reply") }
    _ = rx.send([0x67]); rx.close()
    if let b = waitFor(timeout: 10, { vendorInterface(at: nil, bootOnly: true).first }) {
        print(String(format: "bootloader appeared: %04x:%04x at 0x%08x", prop(b, kIOHIDVendorIDKey), prop(b, kIOHIDProductIDKey), prop(b, kIOHIDLocationIDKey)))
    } else { print("no bootloader appeared within 10s") }

case "flash":
    guard args.count > 2 else { fail("usage: kbdfu flash <location> <firmware.dat> [--dry-run] [--model US|UK]") }
    let dryRun = args.contains("--dry-run")
    let modelArg = args.firstIndex(of: "--model").flatMap { $0 + 1 < args.count ? args[$0 + 1].uppercased() : nil }
    if let m = modelArg, keyboardVersions[m] == nil { fail("--model must be US or UK") }
    guard let fw = FileManager.default.contents(atPath: args[2]).map({ [UInt8]($0) }) else { fail("cannot read \(args[2])") }

    // --- validate the firmware file before touching the device
    guard (1024...0x40000).contains(fw.count) else { fail("unexpected firmware size \(fw.count)") }
    guard fw.count > 12, Array(fw[8..<12]) == Array("KNLT".utf8) else { fail("missing Telink KNLT signature at offset 8") }
    let crc = crcNoInv(fw)
    guard crc == 0 else { fail(String(format: "file self-check CRC is 0x%08x, expected 0 (corrupt download?)", crc)) }
    var tlv: [UInt8: String] = [:]
    if let r = fw.indices.first(where: { $0 + 8 <= fw.count && Array(fw[$0..<$0 + 8]) == Array("ABabJDFW".utf8) }) {
        var j = r + 8
        while j + 1 < fw.count, fw[j] != 0 {
            let t = fw[j], l = Int(fw[j + 1]); guard j + 2 + l <= fw.count else { break }
            tlv[t] = String(decoding: fw[(j + 2)..<(j + 2 + l)], as: UTF8.self); j += 2 + l
        }
    }
    guard let vendor = tlv[1], let fwVer = tlv[2] else { fail("no ABabJDFW info block in file") }
    guard tlv[3] == nil else { fail("file overrides the address byte (TLV 3); not supported") }
    print("file OK: \(fw.count) bytes, vendor \(vendor), version \(fwVer), CRC self-check 0")

    // --- app mode: switch to bootloader if needed
    var bootDev = first
    guard let rx0 = Receiver(first) else { fail("cannot open device") }
    guard let info0 = ack(rx0.send([0x61]), 0x61) else { fail("bad 0x61 reply") }
    if !inBootloader(info0) {
        print("switching to bootloader...")
        _ = rx0.send([0x67]); rx0.close()
        Thread.sleep(forTimeInterval: 1.0)  // let the old interface go away before polling
        // The bootloader may come back under a new ID (receiver: 5202) or the same one (keyboard), so confirm via 0x61
        guard let b = waitFor(timeout: 10, {
            let cands = vendorInterface(at: loc).isEmpty ? vendorInterface(at: nil, bootOnly: true) : vendorInterface(at: loc)
            guard cands.count == 1 else { return nil }
            guard let probe = Receiver(cands[0]) else { return nil }; defer { probe.close() }
            guard let i = ack(probe.send([0x61], quiet: true), 0x61), inBootloader(i) else { return nil }
            return cands[0]
        }) else { fail("bootloader did not appear within 10s (replug the device to recover)") }
        bootDev = b
        print(String(format: "bootloader connected: %04x:%04x at 0x%08x", prop(b, kIOHIDVendorIDKey), prop(b, kIOHIDProductIDKey), prop(b, kIOHIDLocationIDKey)))
        Thread.sleep(forTimeInterval: 0.5)
    } else { rx0.close() }
    guard let bl = Receiver(bootDev) else { fail("cannot open bootloader (replug the device to recover)") }

    // --- bootloader handshake (dfu4 states 4-6); nothing is modified yet
    guard let v = ack(bl.send([0x60]), 0x60) else { fail("bad 0x60 reply from bootloader") }
    let name = String(decoding: v[10..<min(v.count, 20)].prefix { $0 != 0 }, as: UTF8.self)
    guard name == vendor else { fail("bootloader reports '\(name)', file is for '\(vendor)'") }
    if vendor == "TL 8BiDo" {
        let running = String(decoding: v[22..<min(v.count, 32)].prefix { $0 != 0 }, as: UTF8.self)
        guard let fileModel = keyboardModel(fwVer) else { fail("firmware version \(fwVer) isn't a known US or UK keyboard release; refusing (update keyboardVersions)") }
        let detected = keyboardModel(running)
        if let m = modelArg, let d = detected, m != d { fail("--model \(m) contradicts the running firmware \(running), which is a \(d) release") }
        guard let devModel = modelArg ?? detected else { fail("can't tell whether this keyboard is US or UK from its firmware \(running); pass --model US or --model UK") }
        guard devModel == fileModel else { fail("this is a \(devModel) keyboard but \(fwVer) is \(fileModel) firmware; refusing to flash the wrong layout") }
        print("keyboard model \(devModel) (\(modelArg != nil ? "from --model" : "detected from running \(running)")), file is \(fileModel) firmware")
    }
    guard let bi = ack(bl.send([0x61]), 0x61) else { fail("bad 0x61 reply from bootloader") }
    let proto = Int(bi[10]) | Int(bi[11]) << 8
    guard proto == 1 || proto == 2 else { fail("unknown bootloader protocol \(proto)") }
    guard bi[3] <= 9 || bi[13] == 0 else { fail("device still reports app mode") }
    guard let sp = ack(bl.send([0x62, 0x00]), 0x62), sp[9] == 0 else { fail("set-protocol (0x62) rejected") }
    print("update handshake OK (name \(name), protocol \(proto))")
    if dryRun { print("DRY RUN: stopping before 0x63 (start update). Nothing was erased. If the device switched to its bootloader, replug it to return to normal firmware."); exit(0) }

    // --- point of no return
    print("Start updating")
    guard bl.send([0x63], subtype: 1) != nil else { fail("no reply to 0x63; replug and retry the flash") }
    print("Writing firmware data...")
    var off = 0, lastPct = -1
    while off < fw.count {
        let chunk = Array(fw[off..<min(off + 16, fw.count)])
        var ok = false
        for attempt in 1...5 {
            if let r = bl.send([0x64] + chunk, subtype: 1, quiet: true) {
                guard ack(r, 0x64) != nil else { fail("unexpected write reply at offset \(off): \(hex(r)) — bootloader stays active; retry the flash") }
                if off == 0 { print("   first write reply: \(hex(r))") }
                ok = true; break
            }
            print("   timeout at offset \(off), retry \(attempt)/5")
        }
        guard ok else { fail("write failed at offset \(off); bootloader stays active; retry the flash") }
        off += chunk.count
        let pct = off * 100 / fw.count
        if pct / 10 != lastPct / 10 { print("   \(pct)%"); lastPct = pct }
    }
    print("Verifying...")
    let c = [UInt8(crc & 0xFF), UInt8(crc >> 8 & 0xFF), UInt8(crc >> 16 & 0xFF), UInt8(crc >> 24)]
    guard let vr = ack(bl.send([0x65] + c + c, timeout: 5), 0x65), vr[10] == 0 else { fail("verify failed; bootloader stays active; retry the flash") }
    print("Verify OK, finishing")
    _ = bl.send([0x66]); bl.close()

    // Confirm by reading the version back: the keyboard's app firmware gives the same short 0x61 reply
    // as a bootloader, so 0x61 can't tell the modes apart there
    Thread.sleep(forTimeInterval: 2.0)
    let running = waitFor(timeout: 15, { () -> IOHIDDevice? in
        guard let d = vendorInterface(at: loc).first, let probe = Receiver(d) else { return nil }
        defer { probe.close() }
        guard let v = ack(probe.send([0x60], quiet: true), 0x60) else { return nil }
        let ver = String(decoding: v[22..<min(v.count, 32)].prefix { $0 != 0 }, as: UTF8.self)
        return ver == fwVer ? d : nil
    })
    if running != nil { print("device is running \(fwVer)") }
    else { print("could not confirm \(fwVer) within 15s; replug the device and run `kbdfu version <location>`") }

default: fail("unknown mode \(mode)")
}
