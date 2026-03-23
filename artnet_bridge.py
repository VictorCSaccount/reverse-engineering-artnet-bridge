import ctypes
import win32process
import win32gui
import struct
import socket
import time

# =============================================================================
# Art-Net DMX Bridge - Process Memory Reader
# Extracts DMX data from a running lighting controller via pointer chain
# analysis and XOR decryption, then broadcasts it over Art-Net UDP.
# =============================================================================

# --- Network config ---
DMX_CHANNELS    = 512
BUFFER_SIZE     = 512
ARTNET_IP       = "192.168.1.255"   # Broadcast address, adjust to your subnet
ARTNET_PORT     = 6454
SEND_INTERVAL   = 0.025             # ~40 FPS
DEBUG           = False

# --- Anti-glitch filter ---
# How many consecutive zero-frames to treat as spikes before accepting them
MAX_ZERO_FRAMES = 2

# --- Target process ---
WINDOW_TITLE    = "LightingController"   # Title of the target window
TARGET_DLL      = "Qt5Core.dll"          # Module used as pointer base

# --- Static offsets (obtained via Cheat Engine + Ghidra analysis) ---
OFFSET_BASE     = 0x0054C908

# Pointer chain for universe data (index [2] is replaced dynamically per universe)
BASE_OFFSETS    = [0x30, 0x98, 0x18, 0x10, 0x0]

# Pointer chain for XOR key buffer (universe 2)
XOR_OFFSETS     = [0x30, 0x98, 0x50, 0x10, 0x0]

# Dynamic offset formula for universes: 0x18 + 0x8 * universe_index
UNIVERSE_COUNT  = 100
UNIVERSE_STRIDE = 0x8
UNIVERSE_BASE   = 0x18


# =============================================================================
# Debug helper
# =============================================================================

def dbg(msg):
    if DEBUG:
        print(msg)


# =============================================================================
# Windows process utilities
# =============================================================================

def open_process(window_title):
    """Find the window by title, retrieve its PID, open a read handle."""
    hwnd = win32gui.FindWindow(None, window_title)
    if not hwnd:
        raise RuntimeError(f"Window not found: '{window_title}'")
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    handle = ctypes.windll.kernel32.OpenProcess(
        0x10 | 0x0400,   # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
        False,
        pid
    )
    if not handle:
        raise RuntimeError("Could not open process handle.")
    return handle, pid


def read_memory(h_proc, address, size):
    """Read `size` bytes from `address` in the target process."""
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = ctypes.windll.kernel32.ReadProcessMemory(
        ctypes.c_void_p(h_proc),
        ctypes.c_void_p(address),
        buf,
        ctypes.c_size_t(size),
        ctypes.byref(bytes_read)
    )
    return bytearray(buf) if ok else None


def follow_pointer_chain(h_proc, base, offsets):
    """
    Walk a multi-level pointer chain.
    Each intermediate offset dereferences a 64-bit pointer;
    the final offset is added to the last resolved address.
    """
    addr = base
    for offset in offsets[:-1]:
        tmp = ctypes.create_string_buffer(8)
        ok = ctypes.windll.kernel32.ReadProcessMemory(
            ctypes.c_void_p(h_proc),
            ctypes.c_void_p(addr + offset),
            tmp,
            ctypes.c_size_t(8),
            None
        )
        if not ok:
            return 0
        addr = struct.unpack("Q", tmp.raw)[0]
    return addr + offsets[-1]


def get_module_base(pid, dll_name):
    """Return the base address of a loaded DLL inside the target process."""
    TH32CS_SNAPMODULE = 0x00000018

    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize",       ctypes.c_ulong),
            ("th32ModuleID", ctypes.c_ulong),
            ("th32ProcessID",ctypes.c_ulong),
            ("GlblcntUsage", ctypes.c_ulong),
            ("ProccntUsage", ctypes.c_ulong),
            ("modBaseAddr",  ctypes.POINTER(ctypes.c_byte)),
            ("modBaseSize",  ctypes.c_ulong),
            ("hModule",      ctypes.c_void_p),
            ("szModule",     ctypes.c_wchar * 256),
            ("szExePath",    ctypes.c_wchar * 260),
        ]

    snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    me   = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)

    if not ctypes.windll.kernel32.Module32FirstW(snap, ctypes.byref(me)):
        ctypes.windll.kernel32.CloseHandle(snap)
        return 0

    while True:
        if me.szModule.lower() == dll_name.lower():
            addr = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
            ctypes.windll.kernel32.CloseHandle(snap)
            return addr
        if not ctypes.windll.kernel32.Module32NextW(snap, ctypes.byref(me)):
            break

    ctypes.windll.kernel32.CloseHandle(snap)
    return 0


# =============================================================================
# Art-Net
# =============================================================================

def build_artnet_packet(universe, dmx_data):
    """
    Build a minimal Art-Net ArtDMX packet (OpCode 0x5000).

    Packet layout (from Art-Net 4 spec):
        ID        8 bytes  "Art-Net\0"
        OpCode    2 bytes  0x0050 (little-endian)
        ProtVer   2 bytes  0x000e (big-endian, value = 14)
        Sequence  1 byte   0x00 (disabled)
        Physical  1 byte   0x00
        Universe  2 bytes  (little-endian)
        Length    2 bytes  (big-endian, must be even, min 2, max 512)
        Data      N bytes  DMX512 slot values
    """
    pkt = bytearray()
    pkt += b'Art-Net\x00'
    pkt += b'\x00\x50'
    pkt += b'\x00\x0e'
    pkt += b'\x00'
    pkt += b'\x00'
    pkt += struct.pack('<H', universe)
    pkt += struct.pack('>H', len(dmx_data))
    pkt += bytes(dmx_data[:DMX_CHANNELS])
    return pkt


def send_artnet(sock, ip, universe, dmx_data):
    sock.sendto(build_artnet_packet(universe, dmx_data), (ip, ARTNET_PORT))


# =============================================================================
# Main loop
# =============================================================================

def main():
    print("Searching for lighting controller process...")
    h_proc, pid = open_process(WINDOW_TITLE)
    dbg(f"PID: {pid}")

    base = get_module_base(pid, TARGET_DLL)
    if not base:
        print(f"Could not locate module '{TARGET_DLL}' in process.")
        return
    dbg(f"Module base @ {hex(base)}")

    # Resolve the static pointer anchors from the module
    raw_points = read_memory(h_proc, base + OFFSET_BASE, 8)
    raw_xor    = read_memory(h_proc, base + OFFSET_BASE, 8)
    if not raw_points or not raw_xor:
        print("Failed to read base pointers.")
        return

    base_points = struct.unpack("Q", raw_points)[0]
    base_xor    = struct.unpack("Q", raw_xor)[0]

    # Resolve and snapshot the XOR key buffer once at startup
    xor_addr   = follow_pointer_chain(h_proc, base_xor, XOR_OFFSETS)
    xor_buffer = read_memory(h_proc, xor_addr, BUFFER_SIZE)
    if not xor_buffer:
        print("Failed to read XOR key buffer.")
        return

    # Build UDP socket with broadcast enabled
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Per-channel anti-glitch state for each universe
    zero_counters    = [[0] * DMX_CHANNELS for _ in range(UNIVERSE_COUNT)]
    last_valid       = [[0] * DMX_CHANNELS for _ in range(UNIVERSE_COUNT)]

    # Dynamic per-universe offsets inside the pointer chain
    dynamic_offsets  = [UNIVERSE_BASE + UNIVERSE_STRIDE * i for i in range(UNIVERSE_COUNT)]

    print(f"Broadcasting Art-Net to {ARTNET_IP} | {UNIVERSE_COUNT} universes | ~{1/SEND_INTERVAL:.0f} FPS")
    print("Ctrl+C to stop.")

    try:
        while True:
            for u_idx, dyn_off in enumerate(dynamic_offsets):
                chain    = [0x30, 0x98, dyn_off, 0x10, 0x0]
                dmx_addr = follow_pointer_chain(h_proc, base_points, chain)
                if dmx_addr == 0:
                    continue

                raw = read_memory(h_proc, dmx_addr, BUFFER_SIZE)
                if not raw:
                    continue

                # XOR decryption: each byte is XORed with the corresponding
                # byte from the key buffer that was snapshotted at startup.
                dmx_raw  = [raw[i] ^ xor_buffer[i] for i in range(DMX_CHANNELS)]
                dmx_out  = bytearray(DMX_CHANNELS)

                # Per-channel glitch filter: short zero spikes are suppressed.
                for i in range(DMX_CHANNELS):
                    v = dmx_raw[i]
                    if v == 0:
                        zero_counters[u_idx][i] += 1
                        if zero_counters[u_idx][i] <= MAX_ZERO_FRAMES:
                            dmx_out[i] = last_valid[u_idx][i]   # hold last known value
                        else:
                            dmx_out[i] = 0                       # real blackout
                    else:
                        zero_counters[u_idx][i] = 0
                        dmx_out[i]              = v
                        last_valid[u_idx][i]    = v

                # Art-Net universes are 1-indexed in this implementation
                send_artnet(sock, ARTNET_IP, u_idx + 1, dmx_out)
                dbg(f"Universe {u_idx + 1}: {list(dmx_out[:8])}...")

            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\nStopped by user. Sending blackout frames...")
    finally:
        for u in range(1, UNIVERSE_COUNT + 1):
            send_artnet(sock, ARTNET_IP, u, bytes(DMX_CHANNELS))
        sock.close()
        ctypes.windll.kernel32.CloseHandle(h_proc)
        print("Blackout sent to all universes. Exiting.")


if __name__ == "__main__":
    main()
