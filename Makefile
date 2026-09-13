-include config.mk

BUILD_GO ?= 1
BUILD_RUST ?= 1
BUILD_GLEAM ?= $(if $(wildcard .tools/gleam/bin/gleam),1,0)
BUILD_CPP ?= 1
BUILD_ZIG ?= 0
BUILD_HARE ?= $(if $(shell command -v hare 2>/dev/null),1,0)
BUILD_ADA ?= 0
ADA_CROSED_LEVEL ?= 0
export ADA_CROSED_LEVEL
BUILD_RELAY ?= 1
BUILD_GUARD ?= 1
BUILD_AUTO ?= 1
BUILD_DETECTOR ?= 1
BUILD_PLUGINS ?= 1
BUILD_CROSED ?= 1
BUILD_APP ?= 1
BUILD_ASSISTANTS ?= 1
BUILD_CONTROL ?= 1
BUILD_SLOTS ?= 1
BUILD_PUBLIC6 ?= 1
BUILD_GATE ?= 1
BUILD_MIGRATION ?= 1
BUILD_COMPLIANCE ?= 0
CROSED_LEVEL ?= 0
APP_TRANSPORT ?= 0
QUBES_ISOLATION ?= 0
CROSED_VARIANT_QUBES ?= 1
export CROSED_LEVEL APP_TRANSPORT QUBES_ISOLATION
PREFIX ?= /usr/local
DESTDIR ?=
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: all build core-go core-rust core-gleam test-gleam core-cpp core-hare test-hare core-carp test-carp gate migration i18n crosed-variants public6 public6-variants public6-contract relay guard service-init auto detector plugins package-manager easybuild crosed app-layer extension-system assistants slots control-center android-preflight android-cores android-apk integration-test test check audit package install clean distclean

all: build

NIM ?= nim
NIM_CROSED_LEVEL ?= 0
NIM_FLAGS ?=
.PHONY: core-nim nim-crosed-variant test-nim
core-nim:
	@if printf '#include <rtc/rtc.h>\n' | $${CC:-cc} -E - >/dev/null 2>&1; then \
		$(NIM) c --mm:arc --threads:on -d:release --checks:on --assertions:on --stackTrace:on --lineTrace:on --nimcache:Core-Nim/obj/$(NIM_CROSED_LEVEL) -d:CrosedLevel=$(NIM_CROSED_LEVEL) --passC:-fPIE --passL:-pie --passL:-Wl,-z,relro,-z,now $(NIM_FLAGS) -o:Core-Nim/shadow6-nim Core-Nim/src/shadow6_nim.nim; chmod 0755 Core-Nim/shadow6-nim; \
	else echo 'libdatachannel unavailable; Core-Nim source contract present'; fi

nim-crosed-variant:
	@$(MAKE) core-nim NIM_CROSED_LEVEL=5
	@install -m 0755 Core-Nim/shadow6-nim Core-Nim/shadow6-nim-crosed
	@$(MAKE) core-nim NIM_CROSED_LEVEL=0

test-nim:
	@if test -x Core-Nim/shadow6-nim; then $(NIM) c -r --mm:arc --nimcache:Core-Nim/obj/test --path:Core-Nim/src -o:Core-Nim/test_protocol Core-Nim/tests/test_protocol.nim; $(PYTHON) Core-Nim/test_core.py; else echo 'libdatachannel unavailable; Core-Nim tests skipped'; fi

.PHONY: core-zig test-zig

.PHONY: core-ada test-ada prove-ada ada-crosed-variant
core-ada:
	@gprbuild -p -P Core-Ada/core_ada.gpr -j2
	@install -m 0755 Core-Ada/obj/$(ADA_CROSED_LEVEL)/bin/shadow6-ada Core-Ada/shadow6-ada
	@install -m 0755 Core-Ada/obj/$(ADA_CROSED_LEVEL)/bin/test_cells Core-Ada/test_cells

prove-ada:
	@gnatprove -P Core-Ada/proof.gpr -j2

ada-crosed-variant:
	@$(MAKE) core-ada ADA_CROSED_LEVEL=5
	@install -m 0755 Core-Ada/shadow6-ada Core-Ada/shadow6-ada-crosed
	@$(MAKE) core-ada ADA_CROSED_LEVEL=0

test-ada: core-ada prove-ada ada-crosed-variant
	@Core-Ada/test_cells
	@$(PYTHON) Core-Ada/test_core.py

ifeq ($(BUILD_ADA),1)
build: core-ada
test: test-ada
endif

core-zig:
	@cd Core-Zig && zig build -j1 -Doptimize=ReleaseSafe
	@install -m 0755 Core-Zig/zig-out/bin/shadow6-zig Core-Zig/shadow6-zig

test-zig: core-zig
	@cd Core-Zig && zig build test -j1
	@$(PYTHON) Core-Zig/test_core.py

ifeq ($(BUILD_ZIG),1)
build: core-zig
test: test-zig
endif

build: core-go core-rust core-gleam core-cpp core-hare core-carp gate migration i18n cli online-repository relay guard service-init auto detector plugins package-manager easybuild crosed app-layer extension-system assistants slots control-center public6-contract

core-hare:
ifeq ($(BUILD_HARE),1)
	@command -v hare >/dev/null || { echo 'BUILD_HARE=1 requires the Hare toolchain' >&2; exit 1; }
	@cd Core-Hare && hare build -l sodium -o shadow6-hare src && chmod 0755 shadow6-hare
else
	@echo 'Core-Hare disabled; set BUILD_HARE=1 with the Hare toolchain installed to enable it'
endif

test-hare: core-hare
	@$(PYTHON) Core-Hare/tests/test_contract.py $(if $(filter 1,$(BUILD_HARE)),--binary Core-Hare/shadow6-hare,)
ifeq ($(BUILD_HARE),1)
	@$(PYTHON) Core-Hare/tests/test_runtime.py
endif

core-carp:
	@if test -x .tools/carp-v0.5.5-x86_64-linux/bin/carp || test -n "$(CARP)"; then bash Core-Carp/compile.sh; else echo 'Core-Carp disabled: provision Carp 0.5.5 explicitly'; fi

test-carp:
	@bash Core-Carp/compile.sh
	@$(PYTHON) Core-Carp/tests/test_core.py

i18n:
	@PYTHONPATH=I18n $(PYTHON) -m py_compile I18n/shadow6_i18n.py

cli:
	@PYTHONPATH=CLI $(PYTHON) -m py_compile CLI/shadow6.py

online-repository:
	@PYTHONPATH=Online-Repository $(PYTHON) -m py_compile Online-Repository/shadow6_repo.py Gate/portmap.py

gate:
ifeq ($(BUILD_GATE),1)
	@echo "Building Gate"
	@cd Gate && CGO_ENABLED=0 GOCACHE="$(abspath .tmp/go-build)" go build -buildvcs=false -trimpath -buildmode=pie -ldflags='-s -w -buildid=' -o shadow6-gate .
endif

migration:
ifeq ($(BUILD_MIGRATION),1)
	@PYTHONPATH=Migration $(PYTHON) -m py_compile Migration/shadow6_migrate.py
endif

service-init:
	@PYTHONPATH=Service-Init $(PYTHON) -m py_compile Service-Init/shadow6_init.py

core-go:
ifeq ($(BUILD_GO),1)
	@echo "Building Core-Go"
	@cd Core-Go && bash ./compile.sh
endif

core-rust:
ifeq ($(BUILD_RUST),1)
	@echo "Building Core-Rust"
	@cd Core-Rust && bash ./compile.sh
endif

core-gleam:
ifeq ($(BUILD_GLEAM),1)
	@echo "Building Core-Gleam"
	@cd Core-Gleam && bash ./compile.sh
else
	@echo 'Core-Gleam disabled; provision .tools/gleam to enable it'
endif

test-gleam: core-gleam
ifeq ($(BUILD_GLEAM),1)
	@cd Core-Gleam && PATH="$(abspath .tools/gleam/bin):$(abspath .tools/gleam/otp/bin):$$PATH" gleam test --target erlang
	@$(PYTHON) Core-Gleam/test_contract.py Core-Gleam/shadow6-gleam
	@$(PYTHON) Core-Gleam/test_control.py Core-Gleam/shadow6-gleam
endif

ifeq ($(BUILD_GLEAM),1)
test: test-gleam
endif

core-cpp:
ifeq ($(BUILD_CPP),1)
	@echo "Building Core-Cpp"
	@cd Core-Cpp && bash ./compile.sh
endif

crosed-variants:
	@$(MAKE) core-go core-rust core-gleam CROSED_LEVEL=5 APP_TRANSPORT=1 QUBES_ISOLATION=$(CROSED_VARIANT_QUBES)
	@install -m 0755 Core-Go/shadow6-go Core-Go/shadow6-go-crosed
	@install -m 0755 Core-Rust/shadow6-rust Core-Rust/shadow6-rust-crosed
	@if test "$(BUILD_GLEAM)" = 1; then install -m 0755 Core-Gleam/shadow6-gleam Core-Gleam/shadow6-gleam-crosed; fi
	@$(MAKE) core-go core-rust core-gleam CROSED_LEVEL=0 APP_TRANSPORT=0 QUBES_ISOLATION=0

public6: public6-contract
	@$(MAKE) build BUILD_GO=1 BUILD_RUST=1 BUILD_CPP=1 BUILD_RELAY=1 BUILD_GUARD=1 BUILD_AUTO=1 BUILD_DETECTOR=1 BUILD_PLUGINS=1 BUILD_CROSED=1 BUILD_APP=1 BUILD_ASSISTANTS=1 BUILD_CONTROL=1 BUILD_SLOTS=1 BUILD_PUBLIC6=1 BUILD_COMPLIANCE=0 CROSED_LEVEL=0 APP_TRANSPORT=0 QUBES_ISOLATION=0
	@$(MAKE) public6-variants

public6-variants:
	@$(MAKE) core-go core-rust BUILD_GO=1 BUILD_RUST=1 CROSED_LEVEL=5 APP_TRANSPORT=1 QUBES_ISOLATION=1
	@install -m 0755 Core-Go/shadow6-go Core-Go/shadow6-go-public6
	@install -m 0755 Core-Rust/shadow6-rust Core-Rust/shadow6-rust-public6
	@$(MAKE) core-go core-rust BUILD_GO=1 BUILD_RUST=1 CROSED_LEVEL=0 APP_TRANSPORT=0 QUBES_ISOLATION=0

public6-contract:
ifeq ($(BUILD_PUBLIC6),1)
	@$(PYTHON) -m py_compile Public6/shadow6_public.py
	@$(PYTHON) Public6/shadow6_public.py profile >/dev/null
endif

relay:
ifeq ($(BUILD_RELAY),1)
	@echo "Building C11Relay"
	@cd C11Relay && bash ./compile.sh
endif

core-d:
	@command -v ldc2 >/dev/null || (echo "ldc2 is required for Core-D" >&2; exit 2)
	@mkdir -p Core-D/obj
	@$(CC) -O2 -fPIC -c Core-D/src/platform.c -o Core-D/obj/platform.o
	@$(CC) -O2 -fPIC -c Core-D/src/launcher.c -o Core-D/obj/launcher.o
	@ldc2 -betterC -O2 -release -I Core-D/src -of=Core-D/shadow6-d Core-D/src/main.d Core-D/src/bounded.d Core-D/src/json.d Core-D/src/native.d Core-D/src/packet.d Core-D/src/config.d Core-D/src/websocket.d Core-D/obj/platform.o Core-D/obj/launcher.o -L-lcrypto -L-lssl -L-lsodium
	@chmod 0755 Core-D/shadow6-d

guard:
ifeq ($(BUILD_GUARD),1)
	@echo "Building Guard"
	@cd Guard && bash ./compile.sh
endif

auto:
ifeq ($(BUILD_AUTO),1)
	@$(PYTHON) -m py_compile Auto-Orchestrator/shadow6_auto.py integration/stack_test.py
endif

detector:
ifeq ($(BUILD_DETECTOR),1)
	@$(PYTHON) -m py_compile Detector/detector_core.py Detector/shadow6_detector.py Detector/shadow6_detector_neo.py Detector/watch.py
endif

plugins:
ifeq ($(BUILD_PLUGINS),1)
	@$(PYTHON) -m py_compile Plugin-System/shadow6_plugins.py Plugin-System/sign_plugin.py plugins/*/main.py
	@$(PYTHON) Plugin-System/shadow6_plugins.py list
endif

package-manager:
	@PYTHONPATH=Package-Manager $(PYTHON) -m py_compile Package-Manager/shadow6_pkg.py

easybuild:
	@PYTHONPATH=Package-Manager $(PYTHON) -m py_compile EasyBuild/shadow6_easybuild.py Android/build_android_cores.py

android-preflight:
	@$(PYTHON) Android/check_build_resources.py

android-cores: android-preflight
	@test -n "$(ANDROID_NDK)" || (echo "ANDROID_NDK=/absolute/path/to/ndk is required" >&2; exit 2)
	@$(PYTHON) Android/build_android_cores.py --ndk "$(ANDROID_NDK)"

android-apk: android-cores
	@test -n "$(ANDROID_SDK_ROOT)" || (echo "ANDROID_SDK_ROOT=/absolute/path/to/sdk is required" >&2; exit 2)
	@test -d "$(ANDROID_SDK_ROOT)/platforms/android-36" || (echo "Android SDK API 36 is incomplete" >&2; exit 2)
	@cd Android && if command -v ionice >/dev/null 2>&1; then \
		exec ionice -c 3 nice -n 10 "$(if $(ANDROID_GRADLE),$(ANDROID_GRADLE),gradle)" --no-daemon --no-configuration-cache --max-workers=1 --console=plain --stacktrace assembleDebug; \
	else \
		exec nice -n 10 "$(if $(ANDROID_GRADLE),$(ANDROID_GRADLE),gradle)" --no-daemon --no-configuration-cache --max-workers=1 --console=plain --stacktrace assembleDebug; \
	fi

crosed:
ifeq ($(BUILD_CROSED),1)
	@$(PYTHON) -m py_compile Crosed/crosedctl.py
endif

app-layer:
ifeq ($(BUILD_APP),1)
	@$(PYTHON) -m py_compile Application-Layer/shadow_protocols.py
endif

extension-system:
ifeq ($(BUILD_CROSED)$(BUILD_APP)$(BUILD_PLUGINS)$(BUILD_SLOTS),1111)
	@PYTHONPATH=Crosed:Application-Layer:Plugin-System:Slot-System:Security-Assistants $(PYTHON) -m py_compile Extension-System/shadow6_extensions.py
endif

assistants:
ifeq ($(BUILD_ASSISTANTS),1)
	@$(PYTHON) -m py_compile Security-Assistants/shadow6_security.py Infrastructure-Assistants/shadow6_infra.py
	@$(PYTHON) Security-Assistants/shadow6_security.py list
endif

control-center:
ifeq ($(BUILD_CONTROL),1)
	@PYTHONPATH=Control-Center $(PYTHON) -m py_compile Control-Center/shadow6_control.py
	@PYTHONPATH=Control-Center $(PYTHON) Control-Center/shadow6_control.py schema >/dev/null
endif

slots:
ifeq ($(BUILD_SLOTS),1)
	@PYTHONPATH=Plugin-System:Security-Assistants:Slot-System $(PYTHON) -m py_compile Slot-System/shadow6_slots.py
	@PYTHONPATH=Plugin-System:Security-Assistants:Slot-System $(PYTHON) Slot-System/shadow6_slots.py catalog >/dev/null
endif

integration-test:
ifeq ($(BUILD_GO)$(BUILD_RUST)$(BUILD_AUTO),111)
	@echo "Running single-host full-stack integration tests"
	@$(PYTHON) integration/stack_test.py --engine all
endif

test:
	@$(PYTHON) -m unittest -v test_compliance.py
	@PYTHONPATH=Tools $(PYTHON) -m unittest discover -s Tools -p 'test_*.py' -v
ifeq ($(BUILD_HARE),1)
	@$(MAKE) test-hare
endif
ifeq ($(BUILD_GO),1)
	@cd Core-Go && go test -buildvcs=false -race -count=1 ./...
endif
ifeq ($(BUILD_RUST),1)
	@cd Core-Rust && cargo test --all-targets -- --test-threads=1
endif
ifeq ($(BUILD_CPP),1)
	@cd Core-Cpp && bash ./test.sh
endif
ifeq ($(BUILD_RELAY),1)
	@cd C11Relay && bash ./test.sh
endif
ifeq ($(BUILD_GUARD),1)
	@cd Guard && go test -buildvcs=false -race -count=1 ./...
endif
ifeq ($(BUILD_GATE),1)
	@cd Gate && GOCACHE="$(abspath .tmp/go-build)" go test -buildvcs=false -race -count=1 ./...
endif
	@PYTHONPATH=Migration $(PYTHON) -m unittest -v Migration/test_migrate.py
	@PYTHONPATH=I18n $(PYTHON) -m unittest -v I18n/test_i18n.py
	@PYTHONPATH=CLI $(PYTHON) -m unittest -v CLI/test_shadow6_cli.py
	@PYTHONPATH=Online-Repository $(PYTHON) -m unittest -v Online-Repository/test_repo.py
	@PYTHONPATH=Service-Init $(PYTHON) -m unittest discover -s Service-Init -v
ifeq ($(BUILD_AUTO),1)
	@$(PYTHON) -m unittest discover -s Auto-Orchestrator -v
endif
ifeq ($(BUILD_DETECTOR),1)
	@PYTHONPATH=Detector $(PYTHON) -m unittest discover -s Detector -v
	@PYTHONPATH=Detector $(PYTHON) Detector/shadow6_detector.py --test
	@PYTHONPATH=Detector $(PYTHON) Detector/shadow6_detector_neo.py --test
endif
ifeq ($(BUILD_PLUGINS),1)
	@$(PYTHON) -m unittest -v Plugin-System/test_plugins.py
endif
	@PYTHONPATH=Package-Manager $(PYTHON) -m unittest discover -s Package-Manager -v
	@PYTHONPATH=Package-Manager $(PYTHON) -m unittest discover -s EasyBuild -v
	@$(PYTHON) -m unittest discover -s Android -v
ifeq ($(BUILD_APP),1)
	@$(PYTHON) -m unittest -v Application-Layer/test_protocols.py
endif
ifeq ($(BUILD_CROSED),1)
	@$(PYTHON) -m unittest -v Crosed/test_crosed.py
	@PYTHONPATH=Crosed $(PYTHON) -m unittest -v Crosed/test_feature_contract.py
endif
ifeq ($(BUILD_ASSISTANTS),1)
	@$(PYTHON) -m unittest -v Security-Assistants/test_security.py Infrastructure-Assistants/test_infra.py
endif
ifeq ($(BUILD_CONTROL),1)
	@PYTHONPATH=Control-Center $(PYTHON) -m unittest -v Control-Center/test_control.py
endif
ifeq ($(BUILD_SLOTS),1)
	@PYTHONPATH=Plugin-System:Security-Assistants:Slot-System $(PYTHON) -m unittest -v Slot-System/test_slots.py
endif
ifeq ($(BUILD_CROSED)$(BUILD_APP)$(BUILD_PLUGINS)$(BUILD_SLOTS),1111)
	@PYTHONPATH=Extension-System:Crosed:Application-Layer:Plugin-System:Slot-System:Security-Assistants $(PYTHON) -m unittest -v Extension-System/test_extensions.py
endif
ifeq ($(BUILD_PUBLIC6),1)
	@PYTHONPATH=Public6 $(PYTHON) -m unittest -v Public6/test_public6.py
endif
	@$(MAKE) integration-test BUILD_GO=$(BUILD_GO) BUILD_RUST=$(BUILD_RUST) BUILD_AUTO=$(BUILD_AUTO)

check:
	@PYTHONPATH=CLI:Online-Repository:Gate $(PYTHON) -m py_compile CLI/*.py Online-Repository/*.py Gate/*.py
ifeq ($(BUILD_GO),1)
	@cd Core-Go && go vet -buildvcs=false ./...
endif
ifeq ($(BUILD_RUST),1)
	@cd Core-Rust && cargo clippy --all-targets --all-features -- -D warnings
endif
ifeq ($(BUILD_GUARD),1)
	@cd Guard && go vet -buildvcs=false ./...
endif
ifeq ($(BUILD_GATE),1)
	@cd Gate && GOCACHE="$(abspath .tmp/go-build)" go vet -buildvcs=false ./...
endif
ifeq ($(BUILD_RELAY),1)
	@set -eu; analysis_dir=$$(mktemp -d /tmp/shadow6-c11-analyzer.XXXXXX); \
	trap 'rm -rf "$$analysis_dir"' EXIT HUP INT TERM; \
	cd C11Relay; \
	if $(CC) -fanalyzer -x c -c /dev/null -o "$$analysis_dir/probe.o" >/dev/null 2>&1; then \
		$(CC) -std=c11 -O0 -fanalyzer -Wall -Wextra -Wpedantic -D_GNU_SOURCE -c c11relay.c -o "$$analysis_dir/relay.o"; \
	else \
		echo "Warning: $(CC) does not support -fanalyzer; running syntax checks only" >&2; \
		$(CC) -std=c11 -O0 -Wall -Wextra -Wpedantic -D_GNU_SOURCE -fsyntax-only c11relay.c; \
	fi
endif
	@PYTHONPATH=Control-Center:Slot-System:Service-Init:Package-Manager:Public6:Migration:I18n $(PYTHON) -m py_compile Service-Init/*.py Auto-Orchestrator/shadow6_auto.py integration/stack_test.py Detector/*.py Plugin-System/*.py Package-Manager/*.py EasyBuild/*.py Android/*.py plugins/*/main.py Crosed/*.py Application-Layer/*.py Security-Assistants/*.py Infrastructure-Assistants/*.py Slot-System/*.py Control-Center/*.py Public6/*.py Migration/*.py I18n/*.py shadow6_audit.py

audit:
	@$(PYTHON) shadow6_audit.py

package:
	@bash Tools/package_release.sh

install: build
	@install -d "$(DESTDIR)$(PREFIX)/bin"
	@if test -x Core-Carp/shadow6-carp; then install -m 0755 Core-Carp/shadow6-carp "$(DESTDIR)$(PREFIX)/bin/shadow6-carp"; fi
ifeq ($(BUILD_HARE),1)
	@install -m 0755 Core-Hare/shadow6-hare "$(DESTDIR)$(PREFIX)/bin/shadow6-hare"
endif
ifeq ($(BUILD_GO),1)
	@install -m 0755 Core-Go/shadow6-go "$(DESTDIR)$(PREFIX)/bin/shadow6-go"
endif
ifeq ($(BUILD_RUST),1)
	@install -m 0755 Core-Rust/shadow6-rust "$(DESTDIR)$(PREFIX)/bin/shadow6-rust"
endif
ifeq ($(BUILD_GLEAM),1)
	@install -m 0755 Core-Gleam/shadow6-gleam "$(DESTDIR)$(PREFIX)/bin/shadow6-gleam"
endif
ifeq ($(BUILD_CPP),1)
	@install -m 0755 Core-Cpp/shadow6-cpp "$(DESTDIR)$(PREFIX)/bin/shadow6-cpp"
endif
ifeq ($(BUILD_ZIG),1)
	@install -m 0755 Core-Zig/shadow6-zig "$(DESTDIR)$(PREFIX)/bin/shadow6-zig"
endif
ifeq ($(BUILD_ADA),1)
	@install -m 0755 Core-Ada/shadow6-ada "$(DESTDIR)$(PREFIX)/bin/shadow6-ada"
endif
ifeq ($(BUILD_RELAY),1)
	@install -m 0755 C11Relay/bridge_relay "$(DESTDIR)$(PREFIX)/bin/shadow6-relay"
endif
ifeq ($(BUILD_GUARD),1)
	@install -m 0755 Guard/shadow6-guard "$(DESTDIR)$(PREFIX)/bin/shadow6-guard"
	@install -m 0755 Guard/shadow6-guard-ctl.sh "$(DESTDIR)$(PREFIX)/bin/shadow6-guard-ctl"
endif
ifeq ($(BUILD_GATE),1)
	@install -m 0755 Gate/shadow6-gate "$(DESTDIR)$(PREFIX)/bin/shadow6-gate"
endif
	@install -m 0755 Migration/shadow6_migrate.py "$(DESTDIR)$(PREFIX)/bin/shadow6-migrate"
	@install -m 0755 CLI/shadow6.py "$(DESTDIR)$(PREFIX)/bin/shadow6"
	@install -m 0755 Online-Repository/shadow6_repo.py "$(DESTDIR)$(PREFIX)/bin/shadow6-repo"
	@install -m 0755 Gate/portmap.py "$(DESTDIR)$(PREFIX)/bin/shadow6-portmap"
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/share/shadow6/i18n"
	@install -m 0644 I18n/shadow6_i18n.py I18n/README.md "$(DESTDIR)$(PREFIX)/share/shadow6/i18n/"
ifeq ($(BUILD_AUTO),1)
	@install -m 0755 Auto-Orchestrator/shadow6_auto.py "$(DESTDIR)$(PREFIX)/bin/shadow6-auto"
endif
ifeq ($(BUILD_DETECTOR),1)
	@install -m 0755 Detector/shadow6_detector.py "$(DESTDIR)$(PREFIX)/bin/shadow6-detector"
	@install -m 0755 Detector/shadow6_detector_neo.py "$(DESTDIR)$(PREFIX)/bin/shadow6-detector-neo"
	@install -m 0644 Detector/shadow6_detector.py "$(DESTDIR)$(PREFIX)/bin/shadow6_detector.py"
	@install -m 0644 Detector/shadow6_detector_neo.py "$(DESTDIR)$(PREFIX)/bin/shadow6_detector_neo.py"
	@install -m 0755 Detector/watch.py "$(DESTDIR)$(PREFIX)/bin/shadow6-watch"
	@install -m 0644 Detector/detector_core.py "$(DESTDIR)$(PREFIX)/bin/detector_core.py"
endif
ifeq ($(BUILD_PLUGINS),1)
	@install -m 0755 Plugin-System/shadow6_plugins.py "$(DESTDIR)$(PREFIX)/bin/shadow6-plugins"
	@install -m 0755 Plugin-System/sign_plugin.py "$(DESTDIR)$(PREFIX)/bin/shadow6-sign-plugin"
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/share/shadow6"
	@install -m 0644 Plugin-System/trusted_signers.json "$(DESTDIR)$(PREFIX)/share/shadow6/trusted_signers.json"
	@cp -R plugins "$(DESTDIR)$(PREFIX)/share/shadow6/"
endif
	@install -m 0755 Package-Manager/shadow6_pkg.py "$(DESTDIR)$(PREFIX)/bin/shadow6-pkg"
	@install -m 0755 EasyBuild/shadow6_easybuild.py "$(DESTDIR)$(PREFIX)/bin/shadow6-easybuild"
ifeq ($(BUILD_CROSED),1)
	@install -m 0755 Crosed/crosedctl.py "$(DESTDIR)$(PREFIX)/bin/crosedctl"
endif
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/share/shadow6/modules"
	@install -m 0644 Crosed/feature_contract.py "$(DESTDIR)$(PREFIX)/bin/feature_contract.py"
	@install -m 0644 Crosed/feature_contract.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/feature_contract.py"
ifeq ($(BUILD_APP),1)
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/share/shadow6/application"
	@install -m 0644 Application-Layer/shadow_protocols.py "$(DESTDIR)$(PREFIX)/share/shadow6/application/shadow_protocols.py"
endif
ifeq ($(BUILD_ASSISTANTS),1)
	@install -m 0755 Security-Assistants/shadow6_security.py "$(DESTDIR)$(PREFIX)/bin/shadow6-security"
	@install -m 0755 Infrastructure-Assistants/shadow6_infra.py "$(DESTDIR)$(PREFIX)/bin/shadow6-infra"
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/share/shadow6/assistants"
	@install -m 0644 Security-Assistants/shadow6_security.py "$(DESTDIR)$(PREFIX)/share/shadow6/assistants/shadow6_security.py"
endif
ifeq ($(BUILD_CONTROL),1)
	@install -m 0755 Control-Center/shadow6_control.py "$(DESTDIR)$(PREFIX)/bin/shadow6-control"
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/share/shadow6/modules"
	@install -m 0644 Auto-Orchestrator/shadow6_auto.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_auto.py"
	@install -m 0644 Infrastructure-Assistants/shadow6_infra.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_infra.py"
	@install -m 0644 Plugin-System/shadow6_plugins.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_plugins.py"
	@install -m 0644 Crosed/crosedctl.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/crosedctl.py"
	@install -m 0644 Slot-System/shadow6_slots.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_slots.py"
	@install -m 0644 Application-Layer/shadow_protocols.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow_protocols.py"
	@install -m 0644 Service-Init/shadow6_init.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_init.py"
	@install -m 0644 Package-Manager/shadow6_pkg.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_pkg.py"
	@install -m 0644 Public6/shadow6_public.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_public.py"
	@install -m 0644 Migration/shadow6_migrate.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_migrate.py"
	@install -m 0644 Online-Repository/shadow6_repo.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_repo.py"
	@install -m 0644 Gate/portmap.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/portmap.py"
endif
ifeq ($(BUILD_CROSED)$(BUILD_APP)$(BUILD_PLUGINS)$(BUILD_SLOTS),1111)
	@install -m 0755 Extension-System/shadow6_extensions.py "$(DESTDIR)$(PREFIX)/bin/shadow6-extensions"
	@install -m 0644 Extension-System/shadow6_extensions.py "$(DESTDIR)$(PREFIX)/share/shadow6/modules/shadow6_extensions.py"
endif
ifeq ($(BUILD_SLOTS),1)
	@install -m 0755 Slot-System/shadow6_slots.py "$(DESTDIR)$(PREFIX)/bin/shadow6-slots"
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/share/shadow6/slots"
	@install -m 0644 Slot-System/bindings.example.json "$(DESTDIR)$(PREFIX)/share/shadow6/slots/bindings.example.json"
endif
ifeq ($(BUILD_PUBLIC6),1)
	@install -m 0755 Public6/shadow6_public.py "$(DESTDIR)$(PREFIX)/bin/shadow6-public"
	@install -d -m 0755 "$(DESTDIR)$(PREFIX)/share/shadow6/public6"
	@install -m 0644 Public6/README.md "$(DESTDIR)$(PREFIX)/share/shadow6/public6/README.md"
	@if test -f Core-Go/shadow6-go-public6; then install -m 0755 Core-Go/shadow6-go-public6 "$(DESTDIR)$(PREFIX)/bin/shadow6-go-public6"; fi
	@if test -f Core-Rust/shadow6-rust-public6; then install -m 0755 Core-Rust/shadow6-rust-public6 "$(DESTDIR)$(PREFIX)/bin/shadow6-rust-public6"; fi
endif
ifeq ($(BUILD_COMPLIANCE),1)
	@echo "Compliance changes require explicit manual execution; see 中国内地用户必须执行.sh"
endif
	@echo "Installed selected Shadow6 components under $(DESTDIR)$(PREFIX)"

clean:
	@rm -f Core-Hare/shadow6-hare Core-Go/shadow6-go Core-Go/shadow6-go-crosed Core-Go/shadow6-go-public6 Core-Rust/shadow6-rust Core-Rust/shadow6-rust-crosed Core-Rust/shadow6-rust-public6 Core-Gleam/shadow6-gleam Core-Gleam/shadow6-gleam-crosed Core-Cpp/shadow6-cpp C11Relay/bridge_relay C11Relay/c11relay_test Guard/shadow6-guard Gate/shadow6-gate
	@$(MAKE) -C Core-Gleam clean
	@find Service-Init Auto-Orchestrator Detector Plugin-System Package-Manager EasyBuild Android plugins integration Crosed Application-Layer Security-Assistants Infrastructure-Assistants Slot-System Control-Center Public6 -type d -name __pycache__ -prune -exec rm -rf {} +

distclean: clean
	@rm -f config.mk

# Core-Idris build configuration
IDRIS2 ?= $(if $(wildcard $(CURDIR)/.tools/idris2/bin/idris2),$(CURDIR)/.tools/idris2/bin/idris2,idris2)
BUILD_IDRIS ?= $(shell if test -x "$(IDRIS2)" || command -v "$(IDRIS2)" >/dev/null 2>&1; then echo 1; else echo 0; fi)
IDRIS_CROSED_LEVEL ?= 0
IDRIS_APP_TRANSPORT ?= 0
IDRIS_QUBES_ISOLATION ?= 0
export IDRIS_CROSED_LEVEL IDRIS_APP_TRANSPORT IDRIS_QUBES_ISOLATION

.PHONY: core-idris test-idris idris-crosed-variant

core-idris:
ifeq ($(BUILD_IDRIS),1)
	@echo "Building Core-Idris with Crosed level $(IDRIS_CROSED_LEVEL)..."
	@case "$(IDRIS_CROSED_LEVEL)" in 0) level=L0;; 1) level=L1;; 2) level=L2;; 3) level=L3;; 4) level=L4;; 5) level=L5;; *) level=L0;; esac; \
		printf 'module Shadow6.BuildConfig\n\nimport Shadow6.Types\n\n%%default total\n\npublic export\nBUILD_CROSED_LEVEL : CrosedLevel\nBUILD_CROSED_LEVEL = %s\n\npublic export\nBUILD_APP_TRANSPORT : Bool\nBUILD_APP_TRANSPORT = %s\n\npublic export\nBUILD_QUBES_ISOLATION : Bool\nBUILD_QUBES_ISOLATION = %s\n' "$$level" "$(if $(filter 1,$(IDRIS_APP_TRANSPORT)),True,False)" "$(if $(filter 1,$(IDRIS_QUBES_ISOLATION)),True,False)" > Core-Idris/src/Shadow6/BuildConfig.idr
	@$(CC) -shared -fPIC -O2 -fstack-protector-strong $$(pkg-config --cflags libsodium) \
		Core-Idris/ffi/sodium_ffi.c -o Core-Idris/ffi/libsodium_ffi.so \
		$$(pkg-config --libs libsodium)
	@cd Core-Idris && $(IDRIS2) --build shadow6-idris.ipkg
	@if [ -f Core-Idris/obj/exec/shadow6-idris ]; then \
		install -m 0755 Core-Idris/obj/exec/shadow6-idris Core-Idris/shadow6-idris; \
		if [ -d Core-Idris/obj/exec/shadow6-idris_app ]; then cp -a Core-Idris/obj/exec/shadow6-idris_app Core-Idris/; fi; \
		echo "✓ Core-Idris built successfully"; \
	elif [ -f Core-Idris/build/exec/shadow6-idris ]; then \
		install -m 0755 Core-Idris/build/exec/shadow6-idris Core-Idris/shadow6-idris; \
		if [ -d Core-Idris/build/exec/shadow6-idris_app ]; then cp -a Core-Idris/build/exec/shadow6-idris_app Core-Idris/; fi; \
		echo "✓ Core-Idris built successfully"; \
	else \
		echo "Warning: Idris2 build completed but binary not found at expected location"; \
	fi
else
	@echo "ERROR: Idris2 not found; install Idris2 or set IDRIS2=/path/to/idris2" >&2
	@exit 1
endif

idris-crosed-variant:
ifeq ($(BUILD_IDRIS),1)
	@echo "Building Core-Idris Crosed L5 variant..."
	@$(MAKE) core-idris IDRIS_CROSED_LEVEL=5 IDRIS_APP_TRANSPORT=1 IDRIS_QUBES_ISOLATION=1
	@if [ -f Core-Idris/shadow6-idris ]; then \
		install -m 0755 Core-Idris/shadow6-idris Core-Idris/shadow6-idris-crosed; \
		echo "✓ Crosed variant saved"; \
	fi
	@echo "Rebuilding default L0 variant..."
	@$(MAKE) core-idris IDRIS_CROSED_LEVEL=0 IDRIS_APP_TRANSPORT=0 IDRIS_QUBES_ISOLATION=0
else
	@echo "ERROR: Idris2 not found; cannot build Crosed variant" >&2
	@exit 1
endif

test-idris: core-idris
ifeq ($(BUILD_IDRIS),1)
	@if [ -x Core-Idris/shadow6-idris ]; then \
		echo "Testing Core-Idris feature contract..."; \
		LD_LIBRARY_PATH="$(CURDIR)/Core-Idris/ffi:$${LD_LIBRARY_PATH:-}" $(PYTHON) Core-Idris/test_core.py; \
	else \
		echo "Core-Idris binary not found; tests skipped"; \
	fi
else
	@echo "ERROR: Idris2 not found; cannot run Idris tests" >&2
	@exit 1
endif

ifeq ($(BUILD_IDRIS),1)
build: core-idris
test: test-idris
crosed-variants: idris-crosed-variant
endif
