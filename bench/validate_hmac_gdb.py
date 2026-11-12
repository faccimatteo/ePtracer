# gdb script (python): dynamic validation of the HMAC key setup fallback.
#
# Loaded by bench/validate_hmac.sh with $funcs_file: lines "VADDR BITS" of the
# SHA-2 block functions tls_anchor found in the executable, and $run_args.
# Every call with a single block whose tail is 0x36 padding is printed as
# "CANDIDATE <key hex>": exactly what probe_hmac_sha256/512 send to userspace.
import gdb

FUNCS = [l.split() for l in open(str(gdb.parse_and_eval("$funcs_file").string())) if l.strip()]


def reg(name):
    return int(gdb.parse_and_eval("(unsigned long)$" + name))


class BlockBreak(gdb.Breakpoint):
    def __init__(self, addr, bits):
        super().__init__("*%d" % addr, internal=True)
        self.block, self.key = (64, 32) if bits == 256 else (128, 48)

    def stop(self):
        if reg("rdx") != 1:
            return False
        b = bytes(gdb.selected_inferior().read_memory(reg("rsi"), self.block))
        if all(x == 0x36 for x in b[self.key:]):
            print("CANDIDATE %s" % bytes(x ^ 0x36 for x in b[:self.key]).hex(), flush=True)
        return False


class StartBreak(gdb.Breakpoint):
    planted = False

    def stop(self):
        if not StartBreak.planted:
            StartBreak.planted = True
            # the executable is position independent: find where it was loaded
            exe = gdb.current_progspace().filename
            base = None
            for line in gdb.execute("info proc mappings", to_string=True).splitlines():
                parts = line.split()
                # the mapping of file offset 0 is the first loaded segment
                if len(parts) >= 5 and parts[-1] == exe and int(parts[3], 16) == 0:
                    base = int(parts[0], 16)
                    break
            for vaddr, bits in FUNCS:
                BlockBreak(base + int(vaddr, 16), int(bits))
            print("HMAC-BASE 0x%x, %d functions" % (base, len(FUNCS)), flush=True)
        return False


gdb.execute("set breakpoint pending on")
gdb.execute("set confirm off")
StartBreak("main", internal=True)
gdb.execute("run " + str(gdb.parse_and_eval("$run_args").string()))
