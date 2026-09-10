#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sys.h"
#include "erl_vm.h"
#include "global.h"
#include <stddef.h>
#include <stdlib.h>

extern void erl_start(int argc, char **argv);

int main(int argc, char **argv) {
    static char *fixed[] = {
      "shadow6-gleam", "-S", "4:4", "-SDcpu", "2:2", "-SDio", "2",
      "--", "-root", "/shadow6-rom", "-bindir", "/shadow6-rom/bin",
      "-progname", "shadow6-gleam", "--", "-home", "/", "--",
      "-mode", "embedded", "-noshell", "-noinput", "-boot", "start_clean",
      "-extra"
    };
    const size_t fixed_count = sizeof(fixed) / sizeof(fixed[0]);
    char **beam_argv = calloc(fixed_count + (size_t)argc, sizeof(*beam_argv));
    if (beam_argv == NULL) return 111;
    if (setenv("BINDIR", "/shadow6-rom/bin", 1) != 0) return 111;
    for (size_t i = 0; i < fixed_count; i++) beam_argv[i] = fixed[i];
    for (int i = 1; i < argc; i++) beam_argv[fixed_count + (size_t)i - 1] = argv[i];
    sys_init_signal_stack();
    erl_start((int)(fixed_count + (size_t)argc - 1), beam_argv);
    return 0;
}
