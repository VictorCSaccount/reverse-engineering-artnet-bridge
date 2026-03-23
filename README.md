# Art-Net DMX Bridge — Process Memory Reader

A research and educational project demonstrating how to extract DMX lighting data from a running Windows process using pointer chain analysis and XOR decryption, then broadcast it over the Art-Net protocol.

This was built as a personal deep-dive into Windows internals, reverse engineering tooling, and stage lighting protocols.

---

## What it does

A lighting controller running on Windows keeps its DMX universe data in memory. The values are lightly obfuscated: each byte is XORed with a corresponding byte from a key buffer stored elsewhere in the same process.

The target software interface displays the live DMX levels:

![Target Lighting Controller UI](images/image_1.png)

This tool:
1. Locates the target process by its window title.
2. Resolves multi-level pointer chains to find the DMX data buffers (one per universe) and the XOR key buffer.
3. Decrypts the raw bytes using the XOR key.
4. Applies a per-channel glitch filter to suppress spurious zero-spikes.
5. Broadcasts the result as standard Art-Net ArtDMX UDP packets at ~40 FPS.

The approach is entirely read-only — nothing is written back to the process. This allows the extracted data to drive external 3D visualization software in real-time:

![3D Visualizer Output driven by Bridge](images/image_2.png)

---

## How the internals were discovered

The memory layout was mapped out using a combination of dynamic and static analysis tools:

### Pointer Extraction and Live Memory Analysis
**Cheat Engine** was used to attach to the process, scan for live DMX values, and trace pointer chains back to a stable base address inside a loaded DLL. This allowed for the identification of the specific instructions handling data obfuscation.

![Cheat Engine Pointer Chain Extraction](images/image_4.png)

### Static Binary Analysis
**Ghidra** was utilized to disassemble the binary, confirming pointer dereferencing patterns and identifying the specific XOR operation used for obfuscation. The project files show the mapping of the memory zones and code structures.

![Ghidra Project - Memory Decompilation](images/image_5.png)

* **Manual offset arithmetic** — universes sit at a predictable stride (`0x18 + 0x8 * universe_index`) inside the same pointer tree, so all 100 universes can be read with a single resolved base.

---

## The XOR obfuscation

The controller stores DMX values in an XORed form. The key is another in-memory buffer reachable via a separate pointer chain from the same DLL base. The decryption is a simple byte-by-byte XOR:

```python
dmx_value = raw_byte ^ key_byte