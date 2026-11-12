/* Minimal BPF object loader, to see per-program which ones the verifier accepts
 * on a given kernel. Build against the project's libbpf.a; run on the device.
 *   bpfload <obj.bpf.o>
 * Prints each program's load result; libbpf prints the verifier log on failure. */
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <obj.bpf.o>\n", argv[0]);
		return 2;
	}
	/* default libbpf printer: warnings + the verifier log on failure go to stderr */

	struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "open failed\n");
		return 1;
	}

	/* Load each program on its own, so one rejection does not hide the rest. */
	struct bpf_program *prog;
	int total = 0, ok = 0;
	bpf_object__for_each_program(prog, obj) {
		if (argc > 2 && strcmp(bpf_program__name(prog), argv[2]) != 0)
			continue;
		struct bpf_object *one = bpf_object__open_file(argv[1], NULL);
		struct bpf_program *p, *keep = NULL;
		if (!one)
			continue;
		bpf_object__for_each_program(p, one) {
			if (strcmp(bpf_program__name(p), bpf_program__name(prog)) == 0)
				keep = p;
			else
				bpf_program__set_autoload(p, false);
		}
		if (keep)
			bpf_program__set_log_level(keep, 1);
		int err = bpf_object__load(one);
		total++;
		if (err == 0) {
			ok++;
			printf("  ok    %s\n", bpf_program__name(keep));
		} else {
			printf("  FAIL  %s (%d)\n", bpf_program__name(prog), err);
		}
		bpf_object__close(one);
	}
	printf("%d/%d programs loaded\n", ok, total);
	bpf_object__close(obj);
	return ok == total ? 0 : 1;
}
