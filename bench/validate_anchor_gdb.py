# gdb script (python): dynamic validation of the string-anchor result.
#
# Loaded by bench/validate_anchor.sh with:
#   $anchor_off  vaddr of the keylog function inside libssl (tls_anchor result)
#   $sym_vaddr   vaddr of SSL_new inside libssl (from .dynsym), to find the base
#   $run_args    the s_client command line
#
# A breakpoint on SSL_new computes the load base of libssl and plants a second
# one on base + anchor_off. Every hit prints the label (rsi), and the secret
# (rdx, rcx bytes): the very registers the eBPF uprobe will read at entry.
import gdb

OFF = int(gdb.parse_and_eval("$anchor_off"))
SYM = int(gdb.parse_and_eval("$sym_vaddr"))


def reg(name):
    return int(gdb.parse_and_eval("(unsigned long)$" + name))


class KeylogBreak(gdb.Breakpoint):
    def stop(self):
        inf = gdb.selected_inferior()
        label = bytes(inf.read_memory(reg("rsi"), 64)).split(b"\0")[0].decode("latin1")
        n = reg("rcx")
        secret = bytes(inf.read_memory(reg("rdx"), n)).hex() if 0 < n <= 64 else ""
        print("ANCHOR %s %s" % (label, secret), flush=True)
        return False


class EntryBreak(gdb.Breakpoint):
    planted = False

    def stop(self):
        if not EntryBreak.planted:
            base = int(gdb.parse_and_eval("(unsigned long)&SSL_new")) - SYM
            KeylogBreak("*%d" % (base + OFF), internal=True)
            EntryBreak.planted = True
            print("ANCHOR-BASE 0x%x probe at 0x%x" % (base, base + OFF), flush=True)
        return False


gdb.execute("set breakpoint pending on")
gdb.execute("set confirm off")
EntryBreak("SSL_new", internal=True)
gdb.execute("run " + str(gdb.parse_and_eval("$run_args").string()))
