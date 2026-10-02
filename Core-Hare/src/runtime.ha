use fmt;
use errors;
use io;
use net;
use net::ip;
use net::udp;
use os;
use rt;
use strings;
use time;
use unix::poll;

// Nonblocking receive permits bounded bursts after one readiness check.
fn recv_available(sock: net::socket, buf: []u8, src: *ip::addr, port: *u16) (size | net::error) = {
	let addrsz = size(rt::sockaddr): u32;
	const sockaddr = rt::sockaddr { ... };
	const n = match (rt::recvfrom(sock, buf: *[*]u8, len(buf), rt::MSG_DONTWAIT, &sockaddr, &addrsz)) {
	case let n: size => yield n;
	case let err: rt::errno => return errors::errno(err);
	};
	if (addrsz > size(rt::sockaddr)) return errors::invalid;
	const peer = ip::from_native(sockaddr);
	*src = peer.0; *port = peer.1;
	return n;
};

const WINDOW: size = 256z;
// POSIX POLLNVAL is 0x20; Hare 0.24.2 does not expose it in unix::poll.
const POLLNVAL: i16 = 0x20;

// SHADOW6_APP_FLOW_FD is an optional inherited SOCK_SEQPACKET message source.
// Invalid configured descriptors fail closed; unset preserves the UDP path.
fn flow_fd_from_env() int = {
	const value = match (os::getenv("SHADOW6_APP_FLOW_FD")) {
	case let value: str => yield value;
	case void => return -1;
	};
	if (len(value) == 0) rt::exit(2);
	const value_bytes = strings::toutf8(value);
	let fd = 0;
	for (let i = 0z; i < len(value_bytes); i += 1) {
		const digit = value_bytes[i];
		if (digit < '0' || digit > '9') rt::exit(2);
		const number = (digit - '0'): int;
		if (fd > (2147483647 - number) / 10) rt::exit(2);
		fd = fd * 10 + number;
	};
	let kind = 0;
	let kind_size = size(int): u32;
	if (rt::getsockopt(fd, rt::SOL_SOCKET, rt::SO_TYPE, &kind: *opaque, &kind_size) is rt::errno ||
		kind != rt::SOCK_SEQPACKET) rt::exit(2);
	const flags = match (rt::fcntl(fd, rt::F_GETFL, void)) {
	case let flags: int => yield flags;
	case => rt::exit(2);
	};
	if (rt::fcntl(fd, rt::F_SETFL, flags | rt::O_NONBLOCK) is rt::errno) rt::exit(2);
	return fd;
};

// The window plus ACKs needs more than the default UDP queue on some hosts.
// Keep requests per-socket and bounded; FreeBSD may reject the largest size,
// so try smaller sizes without changing the operator's global socket limits.
fn socket_buffers(sock: net::socket) void = {
	for (let bytes = 1048576; bytes >= 65536; bytes /= 2) {
		if (rt::setsockopt(sock, rt::SOL_SOCKET, rt::SO_RCVBUF,
			&bytes: *opaque, size(int): u32) is int) break;
	};
	for (let bytes = 1048576; bytes >= 65536; bytes /= 2) {
		if (rt::setsockopt(sock, rt::SOL_SOCKET, rt::SO_SNDBUF,
			&bytes: *opaque, size(int): u32) is int) break;
	};
};

fn ready(fd: net::socket, milliseconds: int) bool = {
	let fds = [poll::pollfd { fd = fd, events = poll::event::POLLIN, ... }];
	match (poll::poll(fds, milliseconds: time::duration * time::MILLISECOND)) {
	case let n: uint => return n == 1 && fds[0].revents & poll::event::POLLIN != 0;
	case => return false;
	};
};

fn nonce_number(counter: []u8, domain: u8) u64 = {
	if (len(counter) != 12 || counter[0] != domain || counter[1] != 0 ||
		counter[2] != 0 || counter[3] != 0) return 0;
	let value = 0u64;
	for (let i = 4z; i < 12; i += 1) value = value * 256 + counter[i]: u64;
	return value;
};

fn monotonic_millis() i64 = {
	const instant = time::now(time::clock::MONOTONIC);
	return instant.sec * 1000 + instant.nsec / 1000000;
};

fn send_frame(sock: net::socket, addr: ip::addr, port: u16, key: []u8,
	counter: []u8, packet: []u8, plain: []u8) bool = {
	if (len(counter) != 12 || len(packet) < 1024 || len(plain) < 980) return false;
	let carry = true;
	for (let i = 12z; i > 1; i -= 1) {
		if (carry) { counter[i-1] += 1; carry = counter[i-1] == 0; };
	};
	if (carry || nonce_number(counter, counter[0]) == 0) return false;
	packet[32..44] = counter[..];
	if (chacha(&packet[44], &plain[0], 980, &counter[0], &key[0]) != 0 ||
		generichash(&packet[0], 32, &packet[32], 992, &key[0], 32) != 0) return false;
	return udp::sendto(sock, packet[..1024], addr, port) is size;
};

fn send_ack(sock: net::socket, addr: ip::addr, port: u16, key: []u8,
	counter: []u8, packet: []u8, received_nonce: []u8) bool = {
	let plain: [980]u8 = [0...];
	plain[0] = 255; plain[1] = 255;
	plain[2..14] = received_nonce[..12];
	return send_frame(sock, addr, port, key, counter, packet, plain[..]);
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
		hello[0] = 'S'; hello[1] = '6'; hello[2] = 'W'; hello[3] = '2';
		if (public_x(&hello[32], &ephemeral[0]) != 0 || sign(&hello[64], null, &hello[0], 64, &sk[0]) != 0) return false;
		match (udp::sendto(sock, hello, *addr, *port)) {
		case size => void;
		case let e: net::error => fmt::errorln("request send failed", net::strerror(e))!; return false;
		};
		if (!ready(sock, 5000)) { fmt::errorln("response timeout")!; return false; };
		let source: ip::addr = ip::LOCAL_V6; let source_port = 0u16;
		const n = match (udp::recvfrom(sock, incoming, &source, &source_port)) { case let n: size => yield n; case => return false; };
		if (n != 192 || source_port != *port || !ip::equal(source, *addr) ||
			equal(&incoming[0], &hello[0], 64) != 0 || incoming[64] != 'S' || incoming[65] != '6' ||
			incoming[66] != 'W' || incoming[67] != '2') { fmt::errorln("response source, version, or length rejected", n, source_port, *port)!; return false; };
		if (equal(&incoming[0], &hello[0], 64) != 0) { fmt::errorln("response challenge rejected")!; return false; };
		if (ed25519_verify(&incoming[128], &incoming[0], 128, &c.peer[0]) != 0) { fmt::errorln("response signature rejected")!; return false; };
		if (shared_x(&secret[0], &ephemeral[0], &incoming[96]) != 0) return false;
		for (let i = 0z; i < 192; i += 1) reply[i] = incoming[i];
	} else {
		if (!ready(sock, 30000)) { fmt::errorln("handshake receive timeout")!; return false; };
		const n = match (udp::recvfrom(sock, incoming, addr, port)) { case let n: size => yield n; case => return false; };
		if (n != 128 || incoming[0] != 'S' || incoming[1] != '6' || incoming[2] != 'W' || incoming[3] != '2') { fmt::errorln("handshake length or window version", n)!; return false; };
		if (ed25519_verify(&incoming[64], &incoming[0], 64, &c.peer[0]) != 0) { fmt::errorln("handshake signature rejected")!; return false; };
		for (let i = 0z; i < 64; i += 1) reply[i] = incoming[i];
		random_bytes(&reply[64], 32);
		reply[64] = 'S'; reply[65] = '6'; reply[66] = 'W'; reply[67] = '2';
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
	if (c.role == "broker") {
		const configured_fd = flow_fd_from_env();
		if (configured_fd >= 0) { rt::close(configured_fd)!; rt::exit(2); };
		broker_runtime(c); return;
	};
	const owned_flow_fd = flow_fd_from_env();
	if (owned_flow_fd >= 0 && c.role != "client") rt::exit(2);
	let flow_fd = owned_flow_fd;
	defer if (owned_flow_fd >= 0) rt::close(owned_flow_fd)!;
	const sock = udp::listen(ip::LOCAL_V6, c.listen)!; defer io::close(sock)!;
	socket_buffers(sock);
	let addr: ip::addr = ip::LOCAL_V6; let port = c.target;
	let tx: [32]u8 = [0...]; let rx: [32]u8 = [0...];
	defer wipe(&tx[0], 32); defer wipe(&rx[0], 32);
	let data_counter: [12]u8 = [0...];
	let ack_counter: [12]u8 = [0...]; ack_counter[0] = 1;
	let ack_high = 0u64; let sent = 0u64; let expected = 1u64;
	let pending_count = 0u; let next_retry_scan = 0i64;
	let pending_packets: [262144]u8 = [0...];
	let pending_sequences: [256]u64 = [0...];
	let pending_retries: [256]u8 = [0...];
	let pending_at: [256]i64 = [0...];
	let queued_plain: [250880]u8 = [0...];
	let queued_nonces: [3072]u8 = [0...];
	let queued_sizes: [256]u16 = [0...];
	let queued_sequences: [256]u64 = [0...];
	let local: ip::addr = ip::LOCAL_V6; let local_port = 0u16;
	let packet: [1025]u8 = [0...]; let plain: [980]u8 = [0...];
	let expected_hash: [32]u8 = [0...];
	defer wipe(&plain[0], 980); defer wipe(&queued_plain[0], WINDOW * 980); defer wipe(&queued_nonces[0], WINDOW * 12);
	fmt::println("control ready")!;
	if (!exchange(sock, c, tx[..], rx[..], &addr, &port)) { fmt::errorln("session exchange failed", c.role)!; rt::exit(2); };
	const app = if (c.role == "agent") udp::connect(ip::LOCAL_V6, c.target)! else udp::listen(ip::LOCAL_V6, c.listen + 1)!;
	defer io::close(app)!;
	socket_buffers(app);
	const deadline = time::now(time::clock::MONOTONIC).sec + 300;
	fmt::println("session ready")!;
	let burst = 0z;
	let poller = [
		poll::pollfd { fd = sock, events = poll::event::POLLIN, ... },
		poll::pollfd { fd = if (flow_fd >= 0) flow_fd else app, events = poll::event::POLLIN, ... },
	];
	for (let count = 0z; count < 1000000; count += 1) {
		const now = monotonic_millis();
		if (now / 1000 >= deadline) break;
		if (pending_count != 0 && now >= next_retry_scan) {
			for (let i = 0z; i < WINDOW; i += 1) if (pending_sequences[i] != 0 && now >= pending_at[i]) {
				if (pending_retries[i] >= 8) { fmt::errorln("native retransmission limit reached")!; rt::exit(2); };
				if (udp::sendto(sock, pending_packets[i*1024 .. (i+1)*1024], addr, port) is net::error) rt::exit(2);
				pending_retries[i] += 1; pending_at[i] = now + 100;
			};
			next_retry_scan = now + 5;
		};
		const next_send_slot = ((sent + 1) % WINDOW: u64): size;
		const can_send = pending_count < WINDOW && pending_sequences[next_send_slot] == 0;
		if (!can_send) poller[1].revents = 0;
		if (burst == 0 || (poller[0].revents == 0 && poller[1].revents == 0)) {
			poller[1].events = if (can_send) poll::event::POLLIN else 0;
			if (poll::poll(poller, 1 * time::MILLISECOND) is poll::error) break;
			burst = 256;
		};
		burst -= 1;
		if (poller[0].revents & poll::event::POLLIN != 0) {
			let source: ip::addr = ip::LOCAL_V6; let source_port = 0u16;
			const n = match (recv_available(sock, packet, &source, &source_port)) { case let n: size => yield n; case => poller[0].revents = 0; continue; };
			if (n != 1024 || source_port != port || !ip::equal(source, addr)) continue;
			if (generichash(&expected_hash[0], 32, &packet[32], 992, &rx[0], 32) != 0 || equal(&expected_hash[0], &packet[0], 32) != 0) continue;
			if (chacha(&plain[0], &packet[44], 980, &packet[32], &rx[0]) != 0) continue;
			const payload_len = plain[0]: size * 256 + plain[1]: size;
			if (payload_len > 978 && payload_len != 65535) { wipe(&plain[0], 980); continue; };
			if (packet[32] == 1 && payload_len == 65535) {
				const ack_seq = nonce_number(plain[2..14], 0);
				const ack_packet_seq = nonce_number(packet[32..44], 1);
				const slot = (ack_seq % WINDOW: u64): size;
				if (ack_seq != 0 && ack_packet_seq > ack_high && pending_sequences[slot] == ack_seq) {
					ack_high = ack_packet_seq;
					pending_sequences[slot] = 0; pending_count -= 1;
					wipe(&pending_packets[slot*1024], 1024);
				};
				wipe(&plain[0], 980); continue;
			};
			if (packet[32] != 0) { wipe(&plain[0], 980); continue; };
			const seq = nonce_number(packet[32..44], 0);
			if (seq == 0) { wipe(&plain[0], 980); continue; };
			if (seq < expected) {
				if (!send_ack(sock, addr, port, tx[..], ack_counter[..], packet[..], packet[32..44])) break;
				wipe(&plain[0], 980); continue;
			};
			if (seq - expected >= WINDOW: u64) { wipe(&plain[0], 980); continue; };
			const slot = (seq % WINDOW: u64): size;
			if (queued_sequences[slot] != 0 && queued_sequences[slot] != seq) { wipe(&plain[0], 980); continue; };
			if (queued_sequences[slot] == 0) {
				queued_sequences[slot] = seq; queued_sizes[slot] = payload_len: u16;
				queued_plain[slot*980 .. slot*980+payload_len] = plain[2 .. 2+payload_len];
				queued_nonces[slot*12 .. slot*12+12] = packet[32..44];
			};
			for (let drained = 0z; drained < WINDOW; drained += 1) {
				const slot = (expected % WINDOW: u64): size;
				if (queued_sequences[slot] != expected) break;
				const payload_size = queued_sizes[slot]: size;
				if (c.role == "agent") {
					if (udp::send(app, queued_plain[slot*980 .. slot*980+payload_size]) is net::error) break;
				} else if (local_port != 0) {
					if (udp::sendto(app, queued_plain[slot*980 .. slot*980+payload_size], local, local_port) is net::error) break;
				} else break;
				if (!send_ack(sock, addr, port, tx[..], ack_counter[..], packet[..], queued_nonces[slot*12 .. slot*12+12])) rt::exit(2);
				queued_sequences[slot] = 0; queued_sizes[slot] = 0;
				wipe(&queued_plain[slot*980], 980); wipe(&queued_nonces[slot*12], 12); expected += 1;
			};
			wipe(&plain[0], 980);
		};
		if (flow_fd >= 0 && (poller[1].revents & (poll::event::POLLERR | POLLNVAL)) != 0) {
			fmt::errorln("application flow ingress failed")!; rt::exit(2);
		};
		if ((poller[1].revents & (poll::event::POLLIN | poll::event::POLLHUP)) != 0 && pending_count < WINDOW && pending_sequences[next_send_slot] == 0) {
			let source: ip::addr = ip::LOCAL_V6; let source_port = 0u16;
			const n = if (flow_fd >= 0) {
				match (rt::recv(flow_fd, &packet[0], len(packet), rt::MSG_DONTWAIT | rt::MSG_TRUNC)) {
				case let n: size => yield n;
				case let err: rt::errno => {
					if (err == rt::EAGAIN || err == rt::EINTR) {
						poller[1].revents = 0; continue;
					};
					fmt::errorln("application flow ingress read failed")!; rt::exit(2);
				};
				}
			} else {
				match (recv_available(app, packet, &source, &source_port)) {
				case let n: size => yield n;
				case => poller[1].revents = 0; continue;
				};
			};
			if (flow_fd >= 0 && n == 0) {
				flow_fd = -1; poller[1].fd = -1; poller[1].revents = 0;
				if (pending_count == 0) break;
				continue;
			};
			if (n > 978 || sent >= 1000000) continue;
			if (flow_fd < 0 && c.role == "client") {
				if (local_port != 0 && (source_port != local_port || !ip::equal(source, local))) continue;
				local = source; local_port = source_port;
			};
			wipe(&plain[0], 980); plain[0] = (n / 256): u8; plain[1] = (n % 256): u8;
			plain[2 .. 2+n] = packet[..n];
			data_counter[0] = 0;
			if (!send_frame(sock, addr, port, tx[..], data_counter[..], packet[..], plain[..])) break;
			sent += 1; const seq = nonce_number(data_counter[..], 0); const slot = next_send_slot;
			if (pending_sequences[slot] != 0) { fmt::errorln("bounded send window slot collision")!; rt::exit(2); };
			pending_packets[slot*1024 .. (slot+1)*1024] = packet[..1024];
			pending_sequences[slot] = seq; pending_retries[slot] = 0;
			pending_at[slot] = monotonic_millis() + 100; pending_count += 1;
			wipe(&plain[0], 980);
		};
		if (owned_flow_fd >= 0 && flow_fd < 0 && pending_count == 0) break;
	};
	if (owned_flow_fd >= 0 && (flow_fd >= 0 || pending_count != 0)) rt::exit(2);
};

// One fixed route, with end-to-end signed admission and no data-plane keys.
// Unknown sources, unsolicited replies and oversized datagrams never route.
fn broker_runtime(c: *configuration) void = {
	const sock = udp::listen(ip::LOCAL_V6, c.listen)!;
	defer io::close(sock)!;
	socket_buffers(sock);
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
			if (packet[0] != 'S' || packet[1] != '6' || packet[2] != 'W' || packet[3] != '2' ||
				ed25519_verify(&packet[64], &packet[0], 64, &c.peer[0]) != 0) continue;
			for (let i = 0z; i < 64; i += 1) challenge[i] = packet[i];
			phase = 1; destination = c.target;
		} else if (phase == 1 && port == c.target && n == 192) {
			if (equal(&packet[0], &challenge[0], 64) != 0 || packet[64] != 'S' || packet[65] != '6' ||
				packet[66] != 'W' || packet[67] != '2' ||
				ed25519_verify(&packet[128], &packet[0], 128, &c.agent_peer[0]) != 0) continue;
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
