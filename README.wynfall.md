# Wynfall Image Engine

This repository is stable-diffusion.cpp at release `master-948-228c707` (commit 228c707) plus one small patch queue, published so the build Wynfall Desktop runs is auditable. The code is MIT, as upstream.

What the patch changes in `examples/server` (and nothing else):

1. `--api-key-env NAME`: the server reads its key from that environment variable (not the command line) and refuses to start without one of 16 or more characters.
2. Every route needs `Authorization: Bearer <key>`, compared in constant time.
3. The permissive CORS block is removed. A request that carries an `Origin` header is refused, `OPTIONS` gets 405, and no `Access-Control-*` header is ever sent.
4. A `Host` other than `127.0.0.1:<port>` or `localhost:<port>` is refused (DNS rebinding).
5. The server refuses to bind anywhere but loopback.

`examples/server/guard_test.cpp` attacks the real guard over real HTTP (no model needed). The release workflow runs it before packing.

Upstream gets the same change as a pull request behind flags. When it lands, Wynfall drops this repository and pins upstream.
