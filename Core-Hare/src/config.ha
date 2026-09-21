use fmt;
use fs;
use io;
use os;
use rt;
use strconv;
use strings;
use unix;

type configuration = struct {
	role: str,
	mode: str,
	listen: u16,
	target: u16,
	key: [32]u8,
	peer: [32]u8,
	agent_peer: [32]u8,
	client_port: u16,
};

// This L0 schema deliberately permits only flat ASCII identifiers and integers.
// Escapes, duplicate keys, nested data and unknown fields fail closed.
fn parse_config(input: str) (configuration | void) = {
	let c = configuration { ... };
	c.mode = "simplex";
	let p = 0z;
	const b = strings::toutf8(input);
	let seen = 0u;
	if (!take(b, &p, '{')) return;
	for (true) {
		const k = match (quoted(b, &p)) { case let s: str => yield s; case => return; };
		if (!take(b, &p, ':')) return;
		let bit = 0u;
		switch (k) {
		case "mode" =>
			bit = 32u;
			c.mode = match (quoted(b, &p)) { case let s: str => yield s; case => return; };
			if (c.mode != "simplex" && c.mode != "abc") return;
		case "role" =>
			bit = 1;
			c.role = match (quoted(b, &p)) { case let s: str => yield s; case => return; };
			if (c.role != "agent" && c.role != "client" && c.role != "broker") return;
		case "private_key", "peer_public_key", "agent_public_key" =>
			bit = if (k == "private_key") 2u else if (k == "peer_public_key") 16u else 64u;
			const v = match (quoted(b, &p)) { case let s: str => yield s; case => return; };
			if (len(v) != 64) return;
			const bytes = strings::toutf8(v);
			for (let i = 0z; i < 32; i += 1) {
				const hi = hex_digit(bytes[i * 2]);
				const lo = hex_digit(bytes[i * 2 + 1]);
				if (hi == 255 || lo == 255) return;
				if (bit == 2) c.key[i] = hi * 16 + lo
				else if (bit == 16) c.peer[i] = hi * 16 + lo
				else c.agent_peer[i] = hi * 16 + lo;
			};
		case "listen_port", "target_port", "client_port" =>
			bit = if (k == "listen_port") 4u else if (k == "target_port") 8u else 128u;
			space(b, &p);
			const start = p;
			for (p < len(b) && b[p] >= '0' && b[p] <= '9'; p += 1) void;
			if (p == start || p - start > 5 || b[start] == '0') return;
			const n = match (strconv::stou16(strings::fromutf8_unsafe(b[start..p]))) {
			case let n: u16 => yield n;
			case => return;
			};
			if (n < 1024) return;
			if (bit == 4) c.listen = n else if (bit == 8) c.target = n else c.client_port = n;
		case => return;
		};
		if (seen & bit != 0) return;
		seen |= bit;
		space(b, &p);
		if (p >= len(b)) return;
		if (b[p] == '}') { p += 1; break; };
		if (!take(b, &p, ',')) return;
	};
	space(b, &p);
	if (p != len(b) || c.listen == c.target || c.listen == 65535 || c.listen + 1 == c.target) return;
	if (c.role == "broker") {
		// Broker has public pins only, never either endpoint's private key.
		if (seen != 221u || c.client_port == c.listen || c.client_port == c.target) return;
	} else if (seen != 31u && seen != 63u) return;
	return c;
};

fn space(b: []u8, p: *size) void = {
	for (*p < len(b) && (b[*p] == ' ' || b[*p] == '\n' || b[*p] == '\r' || b[*p] == '\t'); *p += 1) void;
};

fn take(b: []u8, p: *size, c: u8) bool = {
	space(b, p);
	if (*p >= len(b) || b[*p] != c) return false;
	*p += 1;
	return true;
};

fn quoted(b: []u8, p: *size) (str | void) = {
	if (!take(b, p, '"')) return;
	const start = *p;
	for (*p < len(b) && b[*p] != '"'; *p += 1) {
		if (*p - start >= 64 || b[*p] < 32 || b[*p] > 126 || b[*p] == '\\') return;
	};
	if (*p == len(b)) return;
	const end = *p;
	*p += 1;
	return strings::fromutf8_unsafe(b[start..end]);
};
