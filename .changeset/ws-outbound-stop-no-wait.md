---
'@credo-ts/didcomm': patch
---

`DidCommWsOutboundTransport.stop()` no longer waits for the close handshake of its sockets. It drops them right away and emits their closed event once, so `agent.shutdown()` no longer hangs for 30 s (Node), 60 s (Android) or indefinitely (iOS) when the other agent went away silently.
