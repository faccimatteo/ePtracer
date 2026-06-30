#include "vmlinux.h"
#include <asm/unistd.h>
int main() { return __NR_execve; }
