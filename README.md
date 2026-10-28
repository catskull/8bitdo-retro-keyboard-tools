# 8BitDo firmware on macOS

Notes and a small tool from reverse-engineering the 8BitDo Ultimate Software V2 updaters (Mac v1.0.22, Windows v1.37), October 2026.

The Mac app can't update the Retro Keyboard or its 2.4G receiver. The Windows app updates them by running a separate Windows-only tool, `dfu4.exe`. `kbdfu` reimplements that tool's protocol on macOS. It has updated the following devices from a Mac:

| Device | USB ID | Firmware | Result |
|---|---|---|---|
| Retro Keyboard Receiver (×2) | `2dc8:5201` | 1.03 → 1.04 | OK |
| Retro Keyboard | `2dc8:5200` | 1.72 → 1.77 | OK |

**Web updater:** https://catskull.net/8bitdo-retro-keyboard-tools/ (Chrome or Edge, any OS with WebHID)

> **Note:** this project is vibe coded. The reverse engineering, `kbdfu`, the LED tool and the web updater were all built by chatting with an AI coding assistant (Claude). They were tested on the devices above, but nobody has reviewed the code independently. Use at your own risk.

## Layout

```
kbdfu/main.swift          source
kbdfu/kbdfu               arm64 binary (rebuild: xcrun swiftc -O main.swift -o kbdfu)
kbdfu/leds(.swift)        host-side lock LED control: `leds blink|on|off num|caps|scroll`
                          (standard HID LED report, no firmware involved; the power LED isn't host-controlled)
web/updater.html          browser port (WebHID), live at https://catskull.net/8bitdo-retro-keyboard-tools/
                          (Chrome/Edge). Locally: `cd web && python3 -m http.server 8000`,
                          then open http://localhost:8000/updater.html
.github/workflows/        deploys web/ to GitHub Pages on push to master
firmware_catalog/         raw `select` API responses per firmware_type + INDEX.txt
```

## Using kbdfu

```sh
kbdfu list                                   # list keyboards/receivers/bootloaders; sends nothing
kbdfu version <location>                     # 0x60: name + firmware version (read-only)
kbdfu info <location>                        # 0x61: protocol/mode info (read-only)
kbdfu switch <location>                      # receiver only: reboot into its bootloader
kbdfu flash <location> <file.dat> --dry-run  # handshake only, stops before anything is written
kbdfu flash <location> <file.dat>            # real update
```

- **`<location>`** is the USB LocationID shown by `list`, e.g. `0x02146400`. The tool always requires it, so it can't pick the wrong one of two identical receivers. Replugging can change it, so run `list` first.
- **Before flashing**, the tool checks:
  - the file is a Telink image (`KNLT` at offset 8)
  - the CRC self-check comes out to 0
  - the file's `ABabJDFW` info block names the same vendor as the device reports (`8BITDO` for the receiver, `TL 8BiDo` for the keyboard)
- **Every reply** must echo both the command and the request's sequence number.
- **Keep another input device handy**, because a keyboard or receiver can't type while it updates. If a receiver is left in bootloader mode (`2dc8:5202`), replug it. If a flash failed after "Start updating", run the flash again.

Get firmware from 8BitDo's API. The catalog is in `firmware_catalog/INDEX.txt`:

```sh
curl -s -X POST https://support.8bitdo.com/restapi/link/v1/client/firmware/select \
  -H 'Content-Type: application/json' -d '{"beta":1,"firmware_type":"62"}'
```

Each entry has `fileURL`, `file_version`, `fileSize` and `readme_en`.
- **`md5`:** this field does *not* match a plain MD5 of the file. That's also true for files the official Mac app downloads. Check integrity with the file's built-in CRC instead; see below.
- **`checkversion` and `download`:** the apps also call these. The download link works without them.

## Protocol (from dfu4.exe)

### Transport

Everything goes over HID usage page `0x8C`. Requests are output report `0xB2` and replies are input report `0xB1`, both 33 bytes including the report ID. The app firmware and the receiver's bootloader expose the same interface.

```
request: B2 AA 55+sub len ~len seq <cmd data...> sumLo sumHi 00...
reply:   B1 AA 55     len ~len devSeq type echoSeq cmd status ...
```

- **`AA`:** the address byte. A firmware file could override it with info-block tag 3; none of these files does.
- **`sub`:** the subtype. It's 0 except for `0x63` and `0x64`, which use 1.
- **`len`:** the data length + 2.
- **`seq`:** counts up from 1 and skips 0.
- **`sum`:** a 16-bit sum of the data bytes.
- **`type`:** `A3` or `A1`.
- **`echoSeq`:** the request's `seq`.
- **Long replies:** if a reply's `len` is above `0x19`, the reply continues in a second report.

### Commands

| Cmd | Data | Purpose | Check |
|---|---|---|---|
| `60` | — | name + version (`dfu4 -r`) | name at [10], version at [22] |
| `61` | — | info / mode | see below |
| `67` | — | switch to bootloader (receiver) | device re-enumerates |
| `62` | `00` | setup ("set protocol"); `00` for raw `.dat`/`.bin` | status [9] = 0 |
| `63` | — (sub 1) | start update (erases/prepares) | reply present |
| `64` | 16 data bytes (sub 1) | write next chunk; no address, the device tracks the offset | reply present (dfu4 retries ×5 on timeout) |
| `65` | crc32 LE ×2 | verify | [10] = 0 |
| `66` | — | finish / reboot | usually no reply (device resets) |

### Reading the `0x61` reply

- **Receiver, normal firmware:** a long reply (len `0x0e`) with protocol 2, and byte [13] = 1, meaning "needs switch". It must get `0x67`, after which it re-enumerates as **`2dc8:5202` "Bootloader device"**. Its bootloader is version 1.0.0, and replugging returns it to normal firmware.
- **Receiver, bootloader:** a short reply (len `0x09`) with protocol 1.
- **Keyboard, normal firmware:** **also** the short protocol-1 reply. It updates in place, with no `0x67` and no separate bootloader. That's why the Windows app passes no bootloader IDs for `5200`.
- **Telink's stock bootloader:** the Windows app also knows `248a:ff08`, probably the bootloader on earlier receivers. None of the units here used it.

### Update sequence

`61` → (`67`, then wait for the bootloader) → `60` (name must match the file) → `61` (protocol 1 or 2) → `62 00` → `63` → `64`×N → `65` → `66`

### Verify CRC

The verify CRC is CRC-32 (polynomial `0xEDB88320`, starting value `0xFFFFFFFF`) **without the final inversion**. Every official file already ends with its own CRC, so this CRC over the whole file is `0`, and `0x65` sends `00000000`. That also makes it a free integrity check on downloads.

## Custom firmware

There's no signature check, only the CRC trailer, so a modified image flashes fine. That was confirmed on the spare receiver, which now enumerates as `kbdfu was here`. To patch an image:

1. Edit the bytes. Keep the file length unchanged, so the size field at `0x18` stays correct.
2. Rewrite the last 4 bytes with the CRC trailer: `crc32(body) ^ 0xFFFFFFFF`, little-endian, over everything except those 4 bytes. That makes the whole-file check come out to 0.
3. Leave the `ABabJDFW` info block alone, because the tool and the bootloader check the vendor name in it.

The USB product name strings are standard USB string descriptors: a length byte, `0x03`, then UTF-16LE text.
- **Receiver:** at `0x6d48`.
- **Keyboard:** at `0x1b920`.

**Brick risk:** a name change leaves the code untouched. A code patch that boots but hangs is different, because the receiver can only reach its bootloader through a working app (`0x67`). Recovering from that would need Telink's single-wire debug (SWS) pin and a programmer. The code is tc32, Telink's own instruction set, which standard disassemblers don't support.

## Why the Mac app doesn't support these

- **Mac app:** its only firmware-flashing framework is `RTKCFU` (Realtek CFU), set up for the R8 mouse and adapter (`5205`/`5206`). It also has 8BitDo's own update protocol for other products.
- **Retro Keyboard and its receiver:** these are Telink-based and use the `dfu4` protocol above. The Mac app has no code for it, and never references `5202` or `248a:ff08`.
- **Windows app:** it runs `dfu4.exe` (a Win32/MFC program) for PIDs `5200`, `5201`, `5209` and `520A`.

## Which devices use this protocol

There are 102 firmware types in the catalog, and exactly 5 of them are Telink images (`KNLT`). Between them they cover every product ID that `dfu4.exe` handles:

| USB ID | Product | firmware_type | Update style | Tested |
|---|---|---|---|---|
| `2dc8:5200` | Retro Keyboard (US) | 61 | in place | ✓ |
| `2dc8:5200` | Retro Keyboard UK | 88 | in place (presumably) | — |
| `2dc8:5201` | Retro Keyboard Receiver | 62 | bootloader `5202` / `248a:ff08` | ✓ |
| `2dc8:5209` | Retro 108 Keyboard | 82 | in place (no bootloader IDs in dfu4 call) | — |
| `2dc8:520A` | Retro 108 Adapter | 83 | bootloader `520C` | — |

Everything else uses other formats and update protocols: the Retro 68, Retro 87 Keyboard X, Numpad, and all controllers.

**US vs UK:** both keyboards report `2dc8:5200` and carry the `TL 8BiDo` tag. The only difference is which model's version history the running firmware belongs to.
- **`kbdfu`:** it has a built-in version table and refuses to flash across models. Use `--model US|UK` if the running version isn't in the table.
- **Web page:** it builds the same table live from types 61 and 88.

## Caveats

- This is reverse-engineered and unofficial. It worked on the devices above. Other models handled by `dfu4.exe` (`5209`, `520A` → bootloader `520C`) haven't been tried.
- `dfu4.exe` also accepts `.jfw` and Intel `.hex` files. `kbdfu` only handles the raw `.dat` images that 8BitDo's API serves.
- USB `bcdDevice` is the version number in the device's USB descriptor:
  - **Receiver:** it's `0x103` in all of its firmware files, so trust `kbdfu version` over USB.
  - **Keyboard:** it matches the firmware version.

## License

The code and docs are released into the public domain under the [Unlicense](LICENSE). That doesn't cover `firmware_catalog/`, which is 8BitDo's data saved from their API.
