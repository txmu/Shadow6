const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize, .link_libc = true });
    const exe = b.addExecutable(.{ .name = "shadow6-zig", .root_module = module });
    exe.pie = true;
    if (target.result.abi == .android) {
        const sysroot = b.option([]const u8, "ndk-sysroot", "Absolute NDK LLVM sysroot (Android only)") orelse @panic("Android requires -Dndk-sysroot=/absolute/path/to/NDK/sysroot");
        if (!std.fs.path.isAbsolute(sysroot)) @panic("NDK sysroot must be absolute");
        const triple = switch (target.result.cpu.arch) {
            .aarch64 => "aarch64-linux-android",
            .x86_64 => "x86_64-linux-android",
            else => @panic("Supported Android ABIs: arm64-v8a and x86_64"),
        };
        const libc = b.addWriteFiles().add("android-libc.conf", b.fmt("include_dir={s}/usr/include\nsys_include_dir={s}/usr/include/{s}\ncrt_dir={s}/usr/lib/{s}\nmsvc_lib_dir=\nkernel32_lib_dir=\ngcc_dir=\n", .{ sysroot, sysroot, triple, sysroot, triple }));
        exe.setLibCFile(libc);
        module.addSystemIncludePath(.{ .cwd_relative = b.fmt("{s}/usr/include/{s}", .{ sysroot, triple }) });
    }
    b.installArtifact(exe);
    module.addCSourceFile(.{ .file = b.path("src/signals.c"), .flags = &.{ "-Wall", "-Wextra", "-Werror" } });
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    b.step("test", "Run protocol, configuration and allocation tests").dependOn(&run.step);
}
