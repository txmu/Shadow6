// Shadow6 Core-Hare: bounded L0 Unix datagram proxy (Linux/FreeBSD).
use fmt;
use fs;
use io;
use net;
use net::ip;
use net::udp;
use os;
use rt;
use strings;
use unix;

const PACKET: size = 1024z;
const TAG: size = 32z;
const NONCE: size = 12z;
const PAYLOAD: size = 980z;
const MAX_CONFIG: size = 1024 * 1024;

@symbol("sodium_init") fn sodium_init() int;
@symbol("crypto_sign_verify_detached") fn ed25519_verify(sig: *u8, msg: *u8, msglen: u64, pubkey: *u8) int;
@symbol("crypto_generichash") fn generichash(out: *u8, outlen: size, msg: *u8, msglen: u64, key: *u8, keylen: size) int;
@symbol("crypto_stream_chacha20_ietf_xor") fn chacha(out: *u8, msg: *u8, n: size, nonce: *u8, key: *u8) int;

export fn valid_packet(p: []u8) bool = len(p) == PACKET;

export fn nonce_increases(previous: []u8, current: []u8) bool = {
	if (len(previous) != NONCE || len(current) != NONCE) return false;
	let greater = false;
	for (let i = 0z; i < NONCE; i += 1) {
		if (current[i] < previous[i]) return false;
		if (current[i] > previous[i]) greater = true;
	};
	return greater;
};

// Strict, allocation-free envelope checks. Control JSON is bounded and rejects
// floats, malformed strings, and nesting deeper than sixteen levels.
export fn strict_json(input: str) bool = {
	if (len(input) == 0 || len(input) > MAX_CONFIG) return false;
	const b = strings::toutf8(input);
	let depth: uint = 0u;
	let quoted = false;
	let escaped = false;
	let key_start: size = 0z;
	for (let i = 0z; i < len(b); i += 1) {
		const c: u8 = b[i];
		if (quoted) {
			if (escaped) { escaped = false; continue; };
			if (c == '\\') { escaped = true; continue; };
			if (c == '"') {
				quoted = false;
				let j = i + 1z;
				for (j < len(b) && (b[j] == ' ' || b[j] == '\n' || b[j] == '\r' || b[j] == '\t'); j += 1) void;
				if (j < len(b) && b[j] == ':' && !known_key(b[key_start..i])) return false;
			};
			continue;
		};
		if (c == '"') {
			quoted = true;
			key_start = i + 1z;
			continue;
		};
		if (c == '{' || c == '[') { depth += 1u; if (depth > 16u) return false; };
		if (c == '}' || c == ']') { if (depth == 0u) return false; depth -= 1u; };
		if (c == '.') return false;
	};
	return !quoted && !escaped && depth == 0u;
};

fn known_key(k: []u8) bool = {
	const keys: [_]str = ["role", "broker", "agent", "client", "id", "private_key", "public_key", "key_hex", "listen_addr", "target_port", "broker_addrs", "broker_pub_key", "agent_pub_key", "client_pub_keys", "allowed_agents", "transport", "auto_close_after"];
	for (let i = 0z; i < len(keys); i += 1) {
		const v = keys[i];
		if (len(k) == len(v) && strings::compare(strings::fromutf8_unsafe(k), v) == 0) return true;
	};
	return false;
};

fn config_key(input: str, out: []u8) bool = {
	const b = strings::toutf8(input);
	const marker = "\"key_hex\":\"";
	const start = strings::index(input, marker);
	if (start is void) return false;
	const at = start as size + len(marker);
	if (at + 64z > len(b)) return false;
	for (let i = 0z; i < 32z; i += 1) {
		const hi = hex_digit(b[at + i * 2z]);
		const lo = hex_digit(b[at + i * 2z + 1z]);
		if (hi == 255u8 || lo == 255u8) return false;
		out[i] = hi * 16u8 + lo;
	};
	return true;
};

fn hex_digit(c: u8) u8 = {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10u8;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10u8;
	return 255u8;
};

fn read_secure(path: str) (str | void) = {
	const file = os::open(path, fs::flag::RDONLY | fs::flag::NOFOLLOW)!;
	defer io::close(file)!;
	const st = os::fstat(file)!;
	if (st.uid != unix::geteuid() || st.mode != (fs::mode::REG | fs::mode::USER_RW) || st.sz == 0 || st.sz > MAX_CONFIG) return;
	let data: []u8 = alloc([0...], MAX_CONFIG);
	const n = match (io::read(file, data)) {
	case let n: size => yield n;
	case io::EOF => { free(data); return; };
	case io::error => { free(data); return; };
	};
	if (n == 0 || n > MAX_CONFIG) { free(data); return; };
	const st2 = os::fstat(file)!;
	if (st2.uid != st.uid || st2.mode != (fs::mode::REG | fs::mode::USER_RW) || st2.mode != st.mode || st2.sz != st.sz) { free(data); return; };
	return strings::fromutf8(data[..n])!;
};

fn feature_report() void = {
	fmt::println("{\"core\":\"shadow6-hare\",\"version\":\"1.0.0\",\"crosed_compiled\":false,\"crosed_max_level\":0,\"app_transport\":false,\"qubes_isolation\":false,\"gate_compiled\":false,\"gate_enabled_by_default\":false,\"utf8\":true,\"crosed_capabilities\":[]}")!;
};

fn daemon(port: u16, target: u16, key: []u8) void = {
	if (sodium_init() < 0) rt::exit(2);
	const sock = match (udp::listen(ip::LOCAL_V6, port)) {
	case let s: net::socket => yield s;
	case net::error => rt::exit(2);
	};
	defer io::close(sock)!;
	const upstream = match (udp::connect(ip::LOCAL_V6, target)) {
	case let s: net::socket => yield s;
	case net::error => rt::exit(2);
	};
	defer io::close(upstream)!;
	let packet: [1024]u8 = [0...];
	let previous: [12]u8 = [0...];
	let plain: [980]u8 = [0...];
	for (true) {
		const n = match (udp::recv(sock, packet[..])) {
		case let n: size => yield n;
		case net::error => continue;
		};
		if (n != 1024 || !nonce_increases(previous[..], packet[32..44])) continue;
		for (let i = 0z; i < 12z; i += 1) previous[i] = packet[32 + i];
		let expected: [32]u8 = [0...];
		if (generichash(&expected[0], 32z, &packet[32], 992u64, &key[0], len(key)) != 0) continue;
		let ok = true;
		for (let i = 0z; i < 32z; i += 1) if (expected[i] != packet[i]) ok = false;
		if (!ok) continue;
		if (chacha(&plain[0], &packet[44], 980z, &packet[32], &key[0]) != 0) continue;
		if (udp::send(upstream, plain[..]) is !size) continue;
	};
};

export fn main() void = {
	const args = os::args;
	if (len(args) == 2 && strings::compare(args[1], "--feature-report") == 0) { feature_report(); return; };
	if (len(args) == 3 && strings::compare(args[1], "--check-config") == 0) {
		const config = match (read_secure(args[2])) { case let s: str => yield s; case => rt::exit(2); };
		defer free(config);
		if (!strict_json(config)) rt::exit(2);
		fmt::println("configuration is valid")!; return;
	};
	if (len(args) == 3 && strings::compare(args[1], "--config") == 0) {
		const config = match (read_secure(args[2])) { case let s: str => yield s; case => rt::exit(2); };
		defer free(config);
		if (!strict_json(config)) rt::exit(2);
		let key: [32]u8 = [0...];
		if (!config_key(config, key[..])) rt::exit(2);
		daemon(4433, 4434, key[..]); return;
	};
	fmt::println("shadow6-hare --config FILE | --check-config FILE | --feature-report")!;
};
