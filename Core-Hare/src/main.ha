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
use time;
use unix::poll;
use encoding::hex;

const PACKET: size = 1024z;
const TAG: size = 32z;
const NONCE: size = 12z;
const PAYLOAD: size = 980z;
const MAX_CONFIG: size = 4096;

@symbol("sodium_init") fn sodium_init() int;
@symbol("crypto_sign_verify_detached") fn ed25519_verify(sig: *u8, msg: *u8, msglen: u64, pubkey: *u8) int;
@symbol("crypto_generichash") fn generichash(out: *u8, outlen: size, msg: *u8, msglen: u64, key: *u8, keylen: size) int;
@symbol("crypto_stream_chacha20_ietf_xor") fn chacha(out: *u8, msg: *u8, n: size, nonce: *u8, key: *u8) int;
@symbol("sodium_memzero") fn wipe(out: *u8, n: size) void;
@symbol("sodium_memcmp") fn equal(a: *u8, b: *u8, n: size) int;
@symbol("randombytes_buf") fn random_bytes(out: *u8, n: size) void;
@symbol("crypto_sign_seed_keypair") fn keypair(pk: *u8, sk: *u8, seed: *u8) int;
@symbol("crypto_sign_detached") fn sign(sig: *u8, n: nullable *u64, msg: *u8, msglen: u64, sk: *u8) int;
@symbol("crypto_scalarmult_curve25519_base") fn public_x(out: *u8, sk: *u8) int;
@symbol("crypto_scalarmult_curve25519") fn shared_x(out: *u8, sk: *u8, pk: *u8) int;

export fn valid_packet(p: []u8) bool = len(p) == PACKET;

export fn nonce_increases(previous: []u8, current: []u8) bool = {
	if (len(previous) != NONCE || len(current) != NONCE) return false;
	for (let i = 0z; i < NONCE; i += 1) {
		if (current[i] != previous[i]) return current[i] > previous[i];
	};
	return false;
};

fn hex_digit(c: u8) u8 = {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10u8;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10u8;
	return 255u8;
};

fn read_secure(path: str) (str | void) = {
	const file = match (os::open(path, fs::flag::RDONLY | fs::flag::NOFOLLOW | fs::flag::NONBLOCK)) {
	case let f: io::file => yield f;
	case => return;
	};
	defer io::close(file)!;
	const st = os::fstat(file)!;
	if (st.uid != unix::geteuid() || st.mode != (fs::mode::REG | fs::mode::USER_RW) || st.sz == 0 || st.sz > MAX_CONFIG) return;
	let data: []u8 = alloc([0...], MAX_CONFIG);
	const n = match (io::read(file, data)) {
	case let n: size => yield n;
	case io::EOF => { free(data); return; };
	case io::error => { free(data); return; };
	};
	if (n == 0 || n != st.sz: size) { wipe(&data[0], len(data)); free(data); return; };
	const st2 = os::fstat(file)!;
	if (st2.uid != st.uid || st2.mode != (fs::mode::REG | fs::mode::USER_RW) || st2.mode != st.mode || st2.sz != st.sz) { free(data); return; };
	return strings::fromutf8(data[..n])!;
};

fn feature_report() void = {
	fmt::println("{\"core\":\"shadow6-hare\",\"version\":\"1.0.0\",\"crosed_compiled\":false,\"crosed_max_level\":0,\"app_transport\":false,\"qubes_isolation\":false,\"gate_compiled\":false,\"gate_enabled_by_default\":false,\"utf8\":true,\"crosed_capabilities\":[]}")!;
};


export fn main() void = {
	const args = os::args;
	if (sodium_init() < 0) rt::exit(2);
	if (len(args) == 2 && (args[1] == "--gen-key" || args[1] == "--keygen")) {
		let seed: [32]u8 = [0...]; let pk: [32]u8 = [0...]; let sk: [64]u8 = [0...];
		random_bytes(&seed[0], 32);
		if (keypair(&pk[0], &sk[0], &seed[0]) != 0) rt::exit(2);
		fmt::print("{\"private_key\":\"")!; hex::encode(os::stdout, seed)!;
		fmt::print("\",\"public_key\":\"")!; hex::encode(os::stdout, pk)!; fmt::println("\"}")!;
		wipe(&seed[0], 32); wipe(&sk[0], 64); return;
	};
	if (len(args) == 2 && strings::compare(args[1], "--feature-report") == 0) { feature_report(); return; };
	if (len(args) == 3 && strings::compare(args[1], "--check-config") == 0) {
		const config = match (read_secure(args[2])) { case let s: str => yield s; case => rt::exit(2); };
		defer { const bytes = strings::toutf8(config); wipe(&bytes[0], len(bytes)); free(config); };
		if (parse_config(config) is void) rt::exit(2);
		fmt::println("configuration is valid")!; return;
	};
	if (len(args) == 3 && strings::compare(args[1], "--config") == 0) {
		const config = match (read_secure(args[2])) { case let s: str => yield s; case => rt::exit(2); };
		defer { const bytes = strings::toutf8(config); wipe(&bytes[0], len(bytes)); free(config); };
		let c = match (parse_config(config)) { case let c: configuration => yield c; case => rt::exit(2); };
		defer wipe(&c.key[0], 32);
		runtime(&c); return;
	};
	fmt::println("shadow6-hare --config FILE | --check-config FILE | --feature-report")!;
	rt::exit(2);
};
