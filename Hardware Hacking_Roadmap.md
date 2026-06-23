# Hardware Hacking & Embedded Security Roadmap

> **Your stack:** Linux · ESP32 · STM32F411 · FPGA  
> **Companion book:** *The Hardware Hacking Handbook* (No Starch Press)

---

## How to Read This Roadmap

Each phase builds on the last. Within each phase you will find **concepts to study**, **hands-on labs** you can run with your hardware, and **checkpoints** to verify readiness before moving on. Time estimates are guidelines — move at your own pace.

```
Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5
  Setup     Recon    Comms    Firmware   Attacks   Advanced
```

---

## Phase 0 — Environment & Tooling Setup
*Estimated time: 1–2 weeks*

### Concepts
- Linux as a security workstation (permissions, device nodes, udev rules)
- Serial console basics and terminal emulators
- Python scripting for hardware automation
- Version control for embedded projects (Git + firmware blobs)

### Tooling to Install

```bash
# Serial / protocol analyzers
sudo apt install minicom screen picocom

# Binary analysis
sudo apt install binutils file strings xxd hexedit

# Firmware tools
pip install binwalk esptool stm32flash

# Logic analyzer software
# Install PulseView / sigrok
sudo apt install sigrok pulseview

# Disassemblers / decompilers
# Ghidra (free, NSA): https://ghidra-sre.org
# Binary Ninja (trial): https://binary.ninja
# radare2
sudo apt install radare2

# Fuzzing & testing
pip install boofuzz scapy

# FPGA tools (adjust for your board vendor)
# Xilinx: Vivado | Intel: Quartus | Lattice: OSS (yosys + nextpnr)
```

### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 0.1 | Set up a Linux serial console to STM32F411 via USB-UART | STM32F411 |
| 0.2 | Flash and talk to ESP32 with `esptool.py`; dump the flash | ESP32 |
| 0.3 | Install Ghidra and open any ARM binary — identify `main()` | Linux |
| 0.4 | Set up a logic analyzer (even a $10 clone) and capture UART TX/RX | All |

### Checkpoint ✅
- [ ] Can communicate with both ESP32 and STM32 over serial
- [ ] Can dump and hexdump a firmware binary
- [ ] Ghidra/radare2 opens an ARM ELF without errors

---

## Phase 1 — Hardware Reconnaissance
*Estimated time: 2–3 weeks*

### Concepts
- PCB reading: identifying chips, test points, JTAG/SWD headers
- Component datasheets: how to find and read them
- Power analysis basics: voltage rails, decoupling caps, reset lines
- Photography and documentation practices

### Skills to Build
- Identifying UART, SPI, I2C, JTAG, SWD headers visually
- Using a multimeter for continuity, voltage probing, resistance measurement
- Mapping unknown pinouts with an oscilloscope or logic analyzer

### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 1.1 | Photograph your STM32F411 board and annotate every header/pad | STM32F411 |
| 1.2 | Find the UART TX pin on the ESP32 with only a logic analyzer (no schematic) | ESP32 |
| 1.3 | Use `binwalk -E firmware.bin` to detect compression/encryption on a real image | Linux |
| 1.4 | Map the SWD pins (SWDIO, SWDCLK, GND) on the STM32 without referring to the docs | STM32F411 |
| 1.5 | Attach OpenOCD to STM32 via SWD and confirm connection | STM32F411 |

### Tools Spotlight
- **OpenOCD** — on-chip debugger, connects to JTAG/SWD
- **STM32CubeProgrammer** — read/write flash, option bytes, RDP level
- **JTAGEnum / jtagulator** — automate JTAG pinout discovery

### Checkpoint ✅
- [ ] Can attach OpenOCD to STM32 via SWD
- [ ] Can identify communication protocol from a logic analyzer capture alone
- [ ] Can extract strings from an unknown firmware binary

---

## Phase 2 — Communication Protocol Analysis
*Estimated time: 3–4 weeks*

### 2A — Wired Protocols

#### Concepts
- UART: baud rate, framing, parity — and how to brute-force baud rate
- SPI: clock polarity/phase (CPOL/CPHA), chip select, full-duplex sniffing
- I2C: address scanning, repeated start, clock stretching
- JTAG: TAP state machine, IR/DR registers, boundary scan
- SWD: ARM's 2-wire debug protocol, DAP, MEM-AP

#### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 2.1 | Write an ESP32 I2C scanner and find all devices on a bus | ESP32 |
| 2.2 | Sniff SPI between ESP32 (master) and an SPI flash chip | ESP32 + Logic Analyzer |
| 2.3 | Enumerate JTAG boundary scan registers on STM32 | STM32F411 |
| 2.4 | Perform a UART man-in-the-middle between two ESP32 boards | 2× ESP32 |
| 2.5 | Use OpenOCD to halt, dump RAM, and resume the STM32 | STM32F411 |

---

### 2B — Wireless Protocols

#### Concepts
- Wi-Fi security: WPA2-PSK handshake, PMKID attack, enterprise RADIUS
- Bluetooth/BLE: advertising, pairing, GATT services, sniffing with Wireshark
- 433 MHz / 315 MHz: OOK/ASK modulation, replay attacks
- Sub-GHz: Z-Wave, Zigbee, LoRa basics

#### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 2.6 | Put ESP32 in promiscuous mode and capture Wi-Fi probe requests | ESP32 |
| 2.7 | Scan BLE advertisements and read GATT characteristics from a target device | ESP32 |
| 2.8 | Implement a Wi-Fi deauth detector on ESP32 | ESP32 |
| 2.9 | Replay a 433 MHz signal (garage door, weather station) with a cheap RF module | ESP32 + RF module |

### Checkpoint ✅
- [ ] Can sniff and decode SPI/I2C/UART without knowing the spec in advance
- [ ] Can capture a BLE GATT service and read characteristics
- [ ] Understand JTAG TAP state machine from memory

---

## Phase 3 — Firmware Analysis & Reverse Engineering
*Estimated time: 4–6 weeks*

### Concepts
- Binary formats: ELF, Intel HEX, raw binary, UF2
- ARM Cortex-M architecture: Thumb-2 ISA, memory map, vector table
- Xtensa LX6/LX7 architecture (ESP32)
- Firmware extraction methods: JTAG dump, flash read via SPI, UART bootloader
- Identifying crypto: constants, entropy analysis, known algorithm patterns
- RTOS internals: FreeRTOS task structures, heap layout

### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 3.1 | Dump ESP32 flash with `esptool.py read_flash` and analyze with `binwalk` | ESP32 |
| 3.2 | Load the dump into Ghidra with the Xtensa processor module; find the `app_main` | Linux |
| 3.3 | Dump STM32F411 flash via SWD with OpenOCD; load into Ghidra ARM Cortex-M | STM32F411 + Linux |
| 3.4 | Find the FreeRTOS task list in RAM of a running STM32 target via OpenOCD | STM32F411 |
| 3.5 | Locate hardcoded Wi-Fi credentials or API keys in an ESP32 firmware dump | ESP32 + Linux |
| 3.6 | Patch a branch instruction in firmware (NOP out a password check) in Ghidra; reflash | ESP32 or STM32 |
| 3.7 | Write a custom Ghidra script to auto-label FreeRTOS task function pointers | Linux |

### Key Ghidra Workflows
```
1. Import binary → set language (ARM:LE:32:Cortex or Xtensa)
2. Set base address (check linker script / datasheet memory map)
3. Define the vector table struct at address 0x08000000 (STM32)
4. Auto-analyze → review entry point → rename functions
5. Search for string cross-references to find interesting code paths
```

### Checkpoint ✅
- [ ] Can take an unknown binary and find 3+ interesting functions in Ghidra
- [ ] Can patch a binary and verify the patch works on real hardware
- [ ] Can identify AES S-box or SHA constants in a hex dump

---

## Phase 4 — Active Attack Techniques
*Estimated time: 4–8 weeks*

### 4A — Debug & Memory Attacks

#### Concepts
- Read Protection (RDP) levels on STM32: RDP0, RDP1, RDP2
- JTAG fuses and lock bits
- Dumping protected flash via fault injection or voltage glitching
- Cold-boot attacks and SRAM forensics

#### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 4.1 | Set STM32 to RDP Level 1; confirm flash read protection via OpenOCD | STM32F411 |
| 4.2 | Build a voltage glitcher with a MOSFET and GPIO (crowbar glitch); try to bypass RDP1 | STM32F411 + ESP32 |
| 4.3 | Use FPGA to generate a precise voltage glitch pulse (sub-microsecond timing) | FPGA |
| 4.4 | Read STM32 SRAM contents after a controlled reset to check for key material | STM32F411 |

---

### 4B — Fault Injection & Glitching

#### Concepts
- Voltage fault injection (VFI): crowbar, undershoot glitching
- Clock fault injection (CFI): clock glitching to skip instructions
- Electromagnetic fault injection (EMFI): targeted EM pulses
- Glitch parameters: offset, width, voltage magnitude

#### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 4.5 | Build an FPGA-based clock glitcher for the STM32 | FPGA + STM32F411 |
| 4.6 | Use the clock glitcher to skip a bootloader authentication check | FPGA + STM32F411 |
| 4.7 | Implement glitch triggering from a UART byte pattern with the FPGA | FPGA |
| 4.8 | Measure glitch success rate vs. offset/width parameters and plot results | Linux |

> 💡 **Why FPGA here?** Precise sub-nanosecond glitch timing is impossible with Linux or ESP32 alone. The FPGA gives deterministic timing with no OS jitter.

---

### 4C — Side-Channel Analysis (SCA)

#### Concepts
- Power analysis: SPA (Simple Power Analysis), DPA (Differential Power Analysis)
- Electromagnetic side-channel leakage
- Timing side-channel attacks (software and hardware)
- Countermeasures: masking, shuffling, constant-time code

#### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 4.9 | Measure power consumption of STM32 AES encryption via a shunt resistor + oscilloscope | STM32F411 |
| 4.10 | Collect 1000+ power traces and perform a DPA attack to recover an AES key | STM32F411 + Linux |
| 4.11 | Implement a timing oracle on ESP32 (non-constant-time strcmp) and exploit it | ESP32 |
| 4.12 | Use Python + `numpy` to automate correlation power analysis (CPA) | Linux |

```python
# CPA skeleton — fill in the measurement and hypothesis logic
import numpy as np

traces = np.load("power_traces.npy")   # shape: (n_traces, n_samples)
plaintexts = np.load("plaintexts.npy") # shape: (n_traces, 16)

# Hamming weight model for AES key byte 0
for key_guess in range(256):
    hw = [bin(pt[0] ^ key_guess).count('1') for pt in plaintexts]
    correlation = np.corrcoef(hw, traces.T)[0, 1:]
    # Track peak correlation per key guess
```

---

### 4D — Firmware & Software Attacks

#### Concepts
- Bootloader vulnerabilities: unsigned update, fallback modes
- Buffer overflows on bare-metal systems (no MMU, no stack canary by default)
- Format string bugs in embedded logging
- Command injection in web UIs served by ESP32

#### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 4.13 | Write a vulnerable ESP32 web server with a command injection bug; exploit it | ESP32 |
| 4.14 | Craft a malformed OTA update for the ESP32 and observe failure behavior | ESP32 |
| 4.15 | Build a stack overflow exploit on a bare-metal STM32 target (return-to-shellcode) | STM32F411 |
| 4.16 | Fuzz an ESP32 HTTP endpoint with `boofuzz` and monitor for crashes via UART | ESP32 + Linux |

### Checkpoint ✅
- [ ] Successfully glitched at least one instruction skip on real hardware
- [ ] Recovered at least 1 byte of AES key via DPA
- [ ] Exploited a software vulnerability running on embedded hardware

---

## Phase 5 — Advanced Topics
*Estimated time: Ongoing*

### 5A — FPGA for Security Research

#### Concepts
- Using FPGA as a custom protocol analyzer (replace expensive equipment)
- FPGA as a man-in-the-middle for SPI/I2C/UART
- Implementing cryptographic accelerators and then attacking them
- Bitstream security: encryption, authentication, and bitstream reverse engineering

#### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 5.1 | Build an FPGA SPI sniffer that logs all traffic to UART | FPGA |
| 5.2 | Implement AES-128 in RTL on the FPGA; perform a DPA attack on it | FPGA + oscilloscope |
| 5.3 | Create an FPGA-based MITM for I2C — intercept and modify packets in real time | FPGA |
| 5.4 | Analyze an unencrypted FPGA bitstream (e.g., Lattice iCE40) with `icestorm` | FPGA + Linux |

---

### 5B — Secure Boot & Trust Chains

#### Concepts
- STM32 option bytes and secure boot configuration
- ESP32 Secure Boot V2 + Flash Encryption
- Chain of trust: ROM → bootloader → application
- Attacking secure boot: glitching the verification step, downgrade attacks

#### Labs

| # | Lab | Hardware |
|---|-----|----------|
| 5.5 | Enable ESP32 Flash Encryption; dump flash and verify it is ciphertext | ESP32 |
| 5.6 | Enable Secure Boot V2 on ESP32; try to flash an unsigned image | ESP32 |
| 5.7 | Configure STM32 RDP Level 2 (⚠️ IRREVERSIBLE on real silicon — use a spare chip) | STM32F411 |
| 5.8 | Attempt to glitch past the ESP32 secure boot signature check | ESP32 + FPGA |

---

### 5C — Build Your Own Lab Targets

| Project | Skills Practiced |
|---------|-----------------|
| Custom "CTF flag" device on STM32 (RDP1, obfuscated firmware) | RE, glitching |
| ESP32 "smart lock" with hardcoded PIN and BLE unlock | BLE sniff, firmware RE |
| FPGA-implemented cipher with weak key schedule | SCA, RTL analysis |
| ESP32 + STM32 connected via encrypted SPI | Protocol MITM, key extraction |

---

### 5D — Capture The Flag (CTF) & Real-World Practice

- **[ångstromCTF](https://angstromctf.com)** — good hardware/embedded challenges
- **[PicoCTF](https://picoctf.org)** — beginner to intermediate binary/hardware
- **[Rhme3](https://github.com/Riscure/rhme3)** — hardware security CTF (archived, excellent)
- **[OpenSecurityTraining2](https://ost2.fyi)** — free in-depth architecture courses
- **[ChipWhisperer Jupyter notebooks](https://github.com/newaetech/chipwhisperer-jupyter)** — free SCA labs

---

## Skills Progress Tracker

| Skill Area | Beginner | Intermediate | Advanced |
|------------|----------|--------------|---------|
| PCB Recon | Phase 0–1 | Phase 1 | Phase 5B |
| Serial/JTAG/SWD | Phase 1 | Phase 2A | Phase 4A |
| Wireless Protocols | Phase 2B | Phase 4D | Phase 5A |
| Firmware RE | Phase 3 | Phase 3 | Phase 5D |
| Glitch/Fault Injection | Phase 4A | Phase 4B | Phase 5C |
| Side-Channel Analysis | Phase 4C | Phase 4C | Phase 5A |
| FPGA Security | Phase 0 | Phase 4B | Phase 5A |
| Secure Boot Attacks | Phase 3 | Phase 4D | Phase 5B |

---

## Essential References

### Books
- *The Hardware Hacking Handbook* — Jasper van Woudenberg & Colin O'Flynn (your current read)
- *Hacking the Xbox* — Andrew "bunnie" Huang (free online, classic)
- *The Art of Exploitation* — Jon Erickson (software vuln fundamentals)
- *Practical IoT Hacking* — Fotios Chantzis et al.

### Datasheets / Docs (bookmark these)
- STM32F411 Reference Manual (RM0383) — ST Microelectronics
- ESP32 Technical Reference Manual — Espressif
- ARM CoreSight Architecture Specification (JTAG/SWD internals)
- JEDEC JESD21C (flash memory command sets)

### Communities
- **[/r/hardwarehacking](https://reddit.com/r/hardwarehacking)** — general community
- **[Hackaday.io](https://hackaday.io)** — project sharing and learning
- **[sigpwny Discord](https://sigpwny.com)** — CTF hardware channels
- **[NewAE Forum](https://forum.newae.com)** — ChipWhisperer / SCA community

---

## Safety & Ethics Reminder

> Always attack hardware **you own** or have **explicit written permission** to test.  
> Document your work. Irreversible operations (RDP Level 2, eFuse burning) should be done on **dedicated "sacrifice" chips**, never production devices.

---

*Last updated: June 2026 — built around Linux + ESP32 + STM32F411 + FPGA*