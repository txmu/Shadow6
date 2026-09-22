use fmt;
use io;
use net;
use net::ip;
use net::udp;
use rt;
use time;
use unix::poll;

fn ready(fd: net::socket, milliseconds: int) bool = {
	let fds = [poll::pollfd { fd = fd, events = poll::event::POLLIN, ... }];
	match (poll::poll(fds, milliseconds: time::duration * time::MILLISECOND)) {
	case let n: uint => return n == 1 && fds[0].revents & poll::event::POLLIN != 0;
	case => return false;
	};
};

fn send_frame(sock: net::socket, addr: ip::addr, port: u16, key: []u8, counter: []u8, packet: []u8, plain: []u8) bool = {
	for (let i = 12z; i > 0; i -= 1) { counter[i-1] += 1; if (counter[i-1] != 0) break; };
	for (let i = 0z; i < 12; i += 1) packet[32+i] = counter[i];
	if (chacha(&packet[44], &plain[0], 980, &counter[0], &key[0]) != 0 || generichash(&packet[0], 32, &packet[32], 992, &key[0], 32) != 0) return false;
	return udp::sendto(sock, packet[..1024], addr, port) is size;
};

// Signed challenge/response binds fresh ephemeral keys to the pinned identities.
fn exchange(sock: net::socket, c: *configuration, tx: []u8, rx: []u8, addr: *ip::addr, port: *u16) bool = {
	let pk: [32]u8 = [0...]; let sk: [64]u8 = [0...];
	let ephemeral: [32]u8 = [0...]; let secret: [32]u8 = [0...];
	defer wipe(&sk[0], 64); defer wipe(&ephemeral[0], 32); defer wipe(&secret[0], 32);
	if (keypair(&pk[0], &sk[0], &c.key[0]) != 0) return false;
	random_bytes(&ephemeral[0], 32);
	let hello: [128]u8 = [0...]; let reply: [192]u8 = [0...]; let incoming: [193]u8 = [0...];
	if (c.role == "client") {
		random_bytes(&hello[0], 32);
		if (public_x(&hello[32], &ephemeral[0]) != 0 || sign(&hello[64], null, &hello[0], 64, &sk[0]) != 0) return false;
		match (udp::sendto(sock, hello, *addr, *port)) {
		case size => void;
		case let e: net::error => fmt::errorln("request send failed", net::strerror(e))!; return false;
		};
		if (!ready(sock, 5000)) { fmt::errorln("response timeout")!; return false; };
		let source: ip::addr = ip::LOCAL_V6; let source_port = 0u16;
		const n = match (udp::recvfrom(sock, incoming, &source, &source_port)) { case let n: size => yield n; case => return false; };
		if (n != 192 || source_port != *port || !ip::equal(source, *addr)) { fmt::errorln("response source or length rejected", n, source_port, *port)!; return false; };
		if (equal(&incoming[0], &hello[0], 64) != 0) { fmt::errorln("response challenge rejected")!; return false; };
		if (ed25519_verify(&incoming[128], &incoming[0], 128, &c.peer[0]) != 0) { fmt::errorln("response signature rejected")!; return false; };
		if (shared_x(&secret[0], &ephemeral[0], &incoming[96]) != 0) return false;
		for (let i = 0z; i < 192; i += 1) reply[i] = incoming[i];
	} else {
		if (!ready(sock, 30000)) { fmt::errorln("handshake receive timeout")!; return false; };
		const n = match (udp::recvfrom(sock, incoming, addr, port)) { case let n: size => yield n; case => return false; };
		if (n != 128) { fmt::errorln("handshake length", n)!; return false; };
		if (ed25519_verify(&incoming[64], &incoming[0], 64, &c.peer[0]) != 0) { fmt::errorln("handshake signature rejected")!; return false; };
		for (let i = 0z; i < 64; i += 1) reply[i] = incoming[i];
		random_bytes(&reply[64], 32);
		if (public_x(&reply[96], &ephemeral[0]) != 0 || shared_x(&secret[0], &ephemeral[0], &reply[32]) != 0) { fmt::errorln("handshake exchange rejected")!; return false; };
		if (sign(&reply[128], null, &reply[0], 128, &sk[0]) != 0) { fmt::errorln("handshake signing failed")!; return false; };
		match (udp::sendto(sock, reply, *addr, *port)) {
		case size => void;
		case let e: net::error => fmt::errorln("handshake response failed", net::strerror(e), *port)!; return false;
		};
	};
	let keys: [64]u8 = [0...]; defer wipe(&keys[0], 64);
	if (generichash(&keys[0], 64z, &reply[0], 128u64, &secret[0], 32z) != 0) { fmt::errorln("key derivation failed")!; return false; };
	for (let i = 0z; i < 32; i += 1) {
		tx[i] = keys[i + (if (c.role == "client") 0z else 32z)];
		rx[i] = keys[i + (if (c.role == "client") 32z else 0z)];
	};
	return true;
};

fn runtime(c: *configuration) void = {
	if (c.role == "broker") { broker_runtime(c); return; };
	const sock = udp::listen(ip::LOCAL_V6, c.listen)!; defer io::close(sock)!;
	let addr: ip::addr = ip::LOCAL_V6; let port = c.target;
	let tx: [32]u8 = [0...]; let rx: [32]u8 = [0...];
	defer wipe(&tx[0], 32); defer wipe(&rx[0], 32);
	fmt::println("control ready")!;
	if (!exchange(sock, c, tx, rx, &addr, &port)) { fmt::errorln("session exchange failed", c.role)!; rt::exit(2); };
	const app = if (c.role == "agent") udp::connect(ip::LOCAL_V6, c.target)! else udp::listen(ip::LOCAL_V6, c.listen + 1)!;
	defer io::close(app)!;
	let local: ip::addr = ip::LOCAL_V6; let local_port = 0u16;
	let packet: [1025]u8 = [0...]; let plain: [980]u8 = [0...];
	let previous: [12]u8 = [0...]; let last_data: [12]u8 = [0...]; let nonce: [12]u8 = [0...]; let expected: [32]u8 = [0...];
	let pending_packet: [1024]u8 = [0...]; let pending_nonce: [12]u8 = [0...];
	let pending = false; let retries = 0u; let retry_at = 0i64;
	defer wipe(&plain[0], 980);
	const deadline = time::now(time::clock::MONOTONIC).sec + 300;
	fmt::println("session ready")!;
	for (let count = 0z; count < 1000000 && time::now(time::clock::MONOTONIC).sec < deadline; count += 1) {
		const now = time::now(time::clock::MONOTONIC).sec;
		if (pending && now >= retry_at) {
			if (retries >= 8) { fmt::errorln("native retransmission limit reached")!; rt::exit(2); };
			if (udp::sendto(sock, pending_packet[..], addr, port) is net::error) break;
			retries += 1; retry_at = now + 1;
		};
		let fds = [poll::pollfd { fd = sock, events = poll::event::POLLIN, ... }, poll::pollfd { fd = app, events = if (pending) 0 else poll::event::POLLIN, ... }];
		if (poll::poll(fds, time::SECOND) is poll::error) break;
		if (fds[0].revents & poll::event::POLLIN != 0) {
			let source: ip::addr = ip::LOCAL_V6; let source_port = 0u16;
			const n = match (udp::recvfrom(sock, packet, &source, &source_port)) { case let n: size => yield n; case => continue; };
			if (n != 1024 || source_port != port || !ip::equal(source, addr)) continue;
			if (generichash(&expected[0], 32, &packet[32], 992, &rx[0], 32) != 0 || equal(&expected[0], &packet[0], 32) != 0) continue;
			if (chacha(&plain[0], &packet[44], 980, &packet[32], &rx[0]) != 0) continue;
			const sz = plain[0]: size * 256 + plain[1]: size;
			if (sz > 978 && sz != 65535) { wipe(&plain[0], 980); continue; };
			// ACKs have their own replay semantics: only the outstanding data
			// nonce can release its slot. They must not advance the data
			// watermark when reordered ahead of an earlier data packet.
			if (sz == 65535) {
				if (pending && equal(&plain[2], &pending_nonce[0], 12) == 0) { pending = false; wipe(&pending_packet[0], 1024); };
				wipe(&plain[0], 980); continue;
			};
			if (sz != 65535 && equal(&packet[32], &last_data[0], 12) == 0) {
				wipe(&plain[0], 980);
				plain[0] = 255; plain[1] = 255;
				for (let i = 0z; i < 12; i += 1) plain[2+i] = last_data[i];
				if (!send_frame(sock, addr, port, tx[..], nonce[..], packet[..1024], plain[..])) break;
				wipe(&plain[0], 980); continue;
			};
			if (!nonce_increases(previous, packet[32..44])) { wipe(&plain[0], 980); continue; };
			if (c.role == "client" && local_port == 0) { wipe(&plain[0], 980); continue; };
			for (let i = 0z; i < 12; i += 1) previous[i] = packet[32+i];
			if (c.role == "agent") { if (udp::send(app, plain[2..2+sz]) is net::error) break; }
			else if (local_port != 0) { if (udp::sendto(app, plain[2..2+sz], local, local_port) is net::error) break; };
			for (let i = 0z; i < 12; i += 1) last_data[i] = previous[i];
			wipe(&plain[0], 980);
			plain[0] = 255; plain[1] = 255;
			for (let i = 0z; i < 12; i += 1) plain[2+i] = last_data[i];
			if (!send_frame(sock, addr, port, tx[..], nonce[..], packet[..1024], plain[..])) break;
			wipe(&plain[0], 980);
		};
		if (fds[1].revents & poll::event::POLLIN != 0) {
			let source: ip::addr = ip::LOCAL_V6; let source_port = 0u16;
			const n = match (udp::recvfrom(app, packet, &source, &source_port)) { case let n: size => yield n; case => continue; };
			if (n > 978) continue;
			if (c.role == "client") {
				if (local_port != 0 && (source_port != local_port || !ip::equal(source, local))) continue;
				local = source; local_port = source_port;
			};
			wipe(&plain[0], 980); plain[0] = (n / 256): u8; plain[1] = (n % 256): u8;
			for (let i = 0z; i < n; i += 1) plain[2+i] = packet[i];
			if (!send_frame(sock, addr, port, tx[..], nonce[..], packet[..1024], plain[..])) break;
			for (let i = 0z; i < 1024; i += 1) pending_packet[i] = packet[i];
			for (let i = 0z; i < 12; i += 1) pending_nonce[i] = nonce[i];
			pending = true; retries = 0; retry_at = time::now(time::clock::MONOTONIC).sec + 1;
			wipe(&plain[0], 980);
		};
	};
};

// One fixed route, with end-to-end signed admission and no data-plane keys.
// Unknown sources, unsolicited replies and oversized datagrams never route.
fn broker_runtime(c: *configuration) void = {
	const sock = udp::listen(ip::LOCAL_V6, c.listen)!;
	defer io::close(sock)!;
	let packet: [1025]u8 = [0...];
	let challenge: [64]u8 = [0...];
	let phase = 0u;
	const started = time::now(time::clock::MONOTONIC).sec;
	let activity = started;
	fmt::println("broker ready")!;
	for (let count = 0z; count < 1000000; count += 1) {
		const now = time::now(time::clock::MONOTONIC).sec;
		if (now - started >= 300 || now - activity >= (if (phase == 2) 60 else 5)) break;
		if (!ready(sock, 1000)) continue;
		let addr: ip::addr = ip::LOCAL_V6; let port = 0u16;
		const n = match (udp::recvfrom(sock, packet, &addr, &port)) {
		case let n: size => yield n;
		case => continue;
		};
		if (!ip::equal(addr, ip::LOCAL_V6)) continue;
		let destination = 0u16;
		if (phase == 0 && port == c.client_port && n == 128) {
			if (ed25519_verify(&packet[64], &packet[0], 64, &c.peer[0]) != 0) continue;
			for (let i = 0z; i < 64; i += 1) challenge[i] = packet[i];
			phase = 1; destination = c.target;
		} else if (phase == 1 && port == c.target && n == 192) {
			if (equal(&packet[0], &challenge[0], 64) != 0 || ed25519_verify(&packet[128], &packet[0], 128, &c.agent_peer[0]) != 0) continue;
			phase = 2; destination = c.client_port;
		} else if (phase == 2 && n == 1024) {
			if (port == c.client_port) destination = c.target
			else if (port == c.target) destination = c.client_port;
		};
		if (destination == 0) continue;
		if (udp::sendto(sock, packet[..n], ip::LOCAL_V6, destination) is net::error) break;
		activity = now;
	};
};
