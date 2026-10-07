"""Bounded third-party 60Hz workload using an exported ApplicationBoundary."""
import selectors
import socket
import struct
import time

FRAME = struct.Struct('!BQd8s')


def game_workload(handle, *, ticks=60, recovery_window=3):
    if type(ticks) is not int or not 1 <= ticks <= 600:
        raise ValueError('invalid bounded game tick count')
    if type(recovery_window) is not int or not 1 <= recovery_window <= 10:
        raise ValueError('invalid bounded recovery window')
    boundary, connection = handle.boundary, handle.socket
    if boundary.max_record is not None and boundary.max_record < FRAME.size:
        raise ValueError('game frame exceeds Profile record limit')
    stream = boundary.semantics == 'stream'
    reliable_control = boundary.reliable is True
    previous = connection.gettimeout()
    selector = selectors.DefaultSelector()
    connection.setblocking(False)
    selector.register(connection,selectors.EVENT_READ)
    pending = bytearray()
    received = bytearray()
    sent, replies, latencies = {}, set(), []
    scheduled = updates_sent = controls_sent = dropped = 0
    started = next_tick = time.monotonic()
    send_deadline = started + ticks/60
    deadline = send_deadline + recovery_window
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if scheduled < ticks and now >= next_tick:
                frames = [(0, scheduled)]
                if reliable_control and scheduled % 15 == 0:
                    frames.append((1, scheduled))
                for kind, sequence in frames:
                    frame = FRAME.pack(kind,sequence,now,b'S6GAMEv1')
                    key = (kind,sequence)
                    if stream:
                        pending.extend(frame); sent[key] = (now,frame)
                    else:
                        try:
                            size = connection.send(frame)
                            if size != len(frame): raise ValueError('partial native game record')
                            sent[key] = (now,frame)
                        except BlockingIOError:
                            dropped += 1
                            continue
                    if kind: controls_sent += 1
                    else: updates_sent += 1
                scheduled += 1
                next_tick += 1/60
                if next_tick < now: next_tick = now + 1/60
            if pending:
                try: del pending[:connection.send(pending)]
                except BlockingIOError: pass
                if len(pending) > 65536: raise ValueError('bounded game queue exceeded')
            if scheduled == ticks and not pending and len(replies) == len(sent): break
            for _key,_flags in selector.select(.005):
                if stream:
                    chunk = connection.recv(65536)
                    if not chunk: raise EOFError('game stream EOF')
                    received.extend(chunk)
                    if len(received)>65536: raise ValueError('bounded game receive queue exceeded')
                    frames=[]
                    while len(received)>=FRAME.size:
                        frames.append(bytes(received[:FRAME.size]));del received[:FRAME.size]
                else:
                    frame,_,flags,_ = connection.recvmsg(boundary.max_record)
                    if flags & socket.MSG_TRUNC: raise ValueError('truncated game record')
                    frames=[frame]
                for frame in frames:
                    if len(frame)!=FRAME.size: raise ValueError('game frame size mismatch')
                    kind,sequence,timestamp,marker = FRAME.unpack(frame)
                    key=(kind,sequence)
                    if marker!=b'S6GAMEv1' or key not in sent or sent[key][1]!=frame:
                        raise ValueError('game payload correctness failure')
                    if key in replies: raise ValueError('duplicate application game record')
                    replies.add(key);latencies.append(time.monotonic()-timestamp)
        ordered = sorted(latencies)
        return {'schema':'shadow6.application-game-workload.v1',
            'applicationSDK':'libshadow6.connect_handle/v1','dataPath':'direct-native-socket',
            'semantics':boundary.semantics, 'requestedTickHz':60,
            'ticksScheduled':scheduled,'updatesSent':updates_sent,'controlsSent':controls_sent,
            'controlFlow': 'declared-reliable' if reliable_control else 'UnsupportedFlowCapability',
            'recordsEchoed':len(replies),'unanswered':len(sent)-len(replies),
            'bytesSent':len(sent)*FRAME.size,'bytesEchoed':len(replies)*FRAME.size,
            'freshnessDrops':dropped, 'payloadCorrectness':'PASS',
            'complete':scheduled == ticks and len(replies)==len(sent) and not pending,
            'rttP95Seconds':ordered[min(len(ordered)-1,int(len(ordered)*.95))] if ordered else None,
            'durationSeconds':time.monotonic()-started,
            'migrationSupported':False}
    finally:
        selector.close()
        connection.settimeout(previous)
