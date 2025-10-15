# PCCC Address Decoder for Wireshark

Decodes Allen-Bradley PCCC (Programmable Controller Communication Commands) encapsulated in CIP/EtherNet/IP packets. Shows you what address is being written and what value.

## What It Does

Parses PCCC function 0xAB (Protected Typed Logical Write with Mask) from legacy Allen-Bradley PLCs. Decodes:
- File addresses (O:0.0/15, N7:10, etc.)
- Bit positions and values (SET/CLEAR)
- Mask operations

Works on MicroLogix 1100, SLC 500, PLC-5 running over EtherNet/IP.

## Install

1. Copy `pccc_decoder.lua` to your Wireshark plugins folder:
   - Windows: `%APPDATA%\Wireshark\plugins\`
   - Linux: `~/.local/lib/wireshark/plugins/`
   - macOS: `~/.config/wireshark/plugins/`

2. Reload: `Ctrl+Shift+L` or restart Wireshark

3. Verify: `Help → About Wireshark → Plugins` - should list `pccc_decoder.lua` with no errors

## Use

**Base filter (shows all PCCC 0xAB commands):**
```
cip.pccc.fnc.code_0f == 0xab
```

**Plugin-provided filters:**
```
pccc_addr.is_write          # All PCCC writes
pccc_addr.bit_value == 1    # SETs
pccc_addr.bit_value == 0    # CLEARs
```

**Create a display filter button:**
1. Type `pccc_addr.is_write` in filter bar
2. Click bookmark icon
3. Save
4. One-click filtering

**Create a macro:**
1. `Analyze → Display Filter Macros`
2. Name: `pccc`
3. Text: `cip.pccc.fnc.code_0f == 0xab`
4. Use as: `${pccc} && ip.addr == 10.3.5.5`

The decoded data appears in the packet details tree under "PCCC Address Decoder". Info column shows `[O:0.0/15=1]` style annotations.

## How It Works

PCCC is Allen-Bradley's 1980s-era data table access protocol. Modern PLCs wrap it in CIP for Ethernet compatibility:
```
┌─────────────────────────┐
│  PCCC Commands (0xAB)   │ ← Plugin decodes this
├─────────────────────────┤
│  CIP Object 0x67        │
├─────────────────────────┤
│  EtherNet/IP            │
├─────────────────────────┤
│  TCP/IP                 │
└─────────────────────────┘
```

The plugin runs as a postdissector - executes after Wireshark's CIP dissector extracts the PCCC payload, then parses the file addressing and mask operations.

**0xAB mask write:** `new = (old & ~mask) | (data & mask)`
- Mask selects which bits to modify
- Data provides new values for those bits

## Limitations

- Only decodes 0xAB writes (reads aren't implemented)
- Tested on MicroLogix 1100; other PLCs may use different PCCC dialects
- Handles two packet formats we've seen empirically - standard (10 bytes) and simplified (9 bytes)
- File type table covers common types; obscure ones show as "Unknown"

## Technical Notes

PCCC addressing uses file numbers and elements:
- File type 0x82 = Output (O:)
- File type 0x89 = Integer (N:)
- Element = word offset
- Subelement = bit mask for bit-level ops

The spec says bytes 6-7 are the selection mask and bytes 8-9 are data. Some PLCs use a simplified format where subelement=0x00 and byte 8 is just a flag. Both work.

## Useful References

- ODVA CIP specs: https://www.odva.org
- DF1/PCCC protocol: Search for "DF1 Protocol and Command Set"
- Lynn August's protocol notes: http://www.iatips.com/pccc_tips.html

## License

MIT License