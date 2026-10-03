#!/bin/sh
# The exploit oracle: exits 0 only when a 64-byte name no longer overflows (AddressSanitizer
# makes the overflow exit non-zero).
./greet "$(printf 'A%.0s' $(seq 64))" >/dev/null 2>&1
