# No implicit CA directory

This directory intentionally contains no OpenSSL hashed CA entries. When selecting
a specific CA file, libcurl uses this directory so an unrelated compiled-in CA
directory cannot broaden the selected trust store. It must remain readable.
PHP cURL converts a null CAPATH to an invalid empty path on some builds, so a
real empty directory is required. Native operating-system TLS backends retain
their own trust behavior.
