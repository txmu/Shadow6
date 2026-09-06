module main;
import bounded, config, json, native;
import core.stdc.stdio : printf, fgets, stdin;
import core.stdc.string : strlen;

@nogc nothrow:

private void usage() { printf("shadow6-d --config FILE [--check-config] | --feature-report | --json-rpc\n"); }

extern(C) int shadow6_d_entry(int argc, char** argv) {
    if (d_init() != 0) return 1;
    if (argc == 2 && equal(argv[1][0 .. strlen(argv[1])], "--feature-report")) {
        printf("%.*s\n", cast(int)features.length, features.ptr); return 0;
    }
    if (argc == 3 && equal(argv[1][0 .. strlen(argv[1])], "--check-config")) {
        Document doc; if (!readConfig(argv[2][0 .. strlen(argv[2])], doc)) return 1;
        printf("Configuration valid for shadow6-d\n"); return 0;
    }
    printf("%.*s\n", cast(int)features.length, features.ptr);
    return argc == 1 ? 0 : 2;
}
