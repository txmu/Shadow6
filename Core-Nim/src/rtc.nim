## Polling API: all Nim allocation and object ownership stays on one thread.
{.compile: "rtc_bridge.c".}
{.passL: "-ldatachannel -lpthread".}
proc wsServer*(host: cstring; port: cint; cert, key: cstring): cint {.importc: "nim_rtc_server".}
proc wsClient*(url: cstring): cint {.importc: "nim_rtc_websocket".}
proc wsAccept*(): cint {.importc: "nim_rtc_accept".}
proc createPeer*(bindAddress: cstring): cint {.importc: "nim_rtc_peer".}
proc createChannel*(pc: cint): cint {.importc: "nim_rtc_channel".}
proc gathered*(): cint {.importc: "nim_rtc_gathered".}
proc isOpen*(id: cint): bool {.importc: "rtcIsOpen", header: "rtc/rtc.h".}
proc isClosed*(id: cint): bool {.importc: "rtcIsClosed", header: "rtc/rtc.h".}
proc buffered*(id: cint): cint {.importc: "rtcGetBufferedAmount", header: "rtc/rtc.h".}
proc sendMessage*(id: cint; data: cstring; size: cint): cint {.importc: "rtcSendMessage", header: "rtc/rtc.h".}
proc receiveMessage*(id: cint; data: pointer; size: ptr cint): cint {.importc: "nim_rtc_receive".}
proc localDescription*(id: cint; kind: cstring): cint {.importc: "rtcSetLocalDescription", header: "rtc/rtc.h".}
proc remoteDescription*(id: cint; sdp, kind: cstring): cint {.importc: "rtcSetRemoteDescription", header: "rtc/rtc.h".}
proc getDescription*(id: cint; buffer: pointer; size: cint): cint {.importc: "rtcGetLocalDescription", header: "rtc/rtc.h".}
proc deletePeer*(id: cint): cint {.importc: "rtcDeletePeerConnection", header: "rtc/rtc.h".}
proc deleteChannelRaw(id: cint): cint {.importc: "rtcDeleteDataChannel", header: "rtc/rtc.h".}
proc deleteWsRaw(id: cint): cint {.importc: "rtcDeleteWebSocket", header: "rtc/rtc.h".}
proc forget(id: cint) {.importc: "nim_rtc_forget".}
proc deleteChannel*(id: cint): cint =
  result = deleteChannelRaw(id)
  forget(id)
proc deleteWs*(id: cint): cint =
  result = deleteWsRaw(id)
  forget(id)
proc deleteServer*(id: cint): cint {.importc: "rtcDeleteWebSocketServer", header: "rtc/rtc.h".}
proc cleanup*() {.importc: "rtcCleanup", header: "rtc/rtc.h".}
