# Vendored WebAuthn library

This directory contains the runtime files from 'lbuchs/WebAuthn', pinned to
commit 'fb4bcee0ea8a5bc25e5dc358172d65bf15b5f419'.

Upstream: https://github.com/lbuchs/WebAuthn

License: MIT; see 'LICENSE'.

The only local source change is in 'src/WebAuthn.php': relative 'require_once'
paths use '__DIR__' so loading is independent of the IP-Symcon working
directory. No verification logic was changed.
