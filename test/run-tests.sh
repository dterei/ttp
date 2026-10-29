#!/usr/bin/env bash
#
# Test suite for ttp.  Run it with the bash you want to test, e.g.
#
#   bash test/run-tests.sh
#   /bin/bash test/run-tests.sh     # bash 3.2 on macOS
#
# ttp itself is run with the same bash.  Requires gpg.  Nothing outside
# a temporary directory is touched; gpg runs with its own GNUPGHOME and a
# fixed passphrase.

# The tests share globals such as hash_in and hash_out with ttp.
# shellcheck disable=SC2034,SC2154

export LC_ALL=C
cd "$(dirname "$0")/.." || exit 1
ttp=$PWD/ttp
tests=0
failures=0

fail() {
    failures=$((failures + 1))
    echo "FAIL: $1"
    shift
    for line in "$@"; do
        echo "      $line"
    done
}

# check NAME EXPECTED ACTUAL
check() {
    tests=$((tests + 1))
    if test "$2" != "$3"; then
        fail "$1" "expected: $2" "actual:   $3"
    fi
}

# check_contains NAME NEEDLE HAYSTACK
check_contains() {
    tests=$((tests + 1))
    case "$3" in
        *"$2"*) ;;
        *) fail "$1" "expected to contain: $2" "actual: $3" ;;
    esac
}

# Set the global array "bytes" to the bytes of string $1.
to_bytes() {
    local i c
    bytes=()
    for ((i = 0; i < ${#1}; i++)); do
        printf -v c '%d' "'${1:i:1}"
        bytes+=("$c")
    done
}

# Set "bytes" to $2 copies of byte $1.
repeat_byte() {
    local i
    bytes=()
    for ((i = 0; i < $2; i++)); do
        bytes+=("$1")
    done
}

hex() {
    printf '%02x' "$@"
}

b32chars=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567

tmp=$(mktemp -d "${TMPDIR:-/tmp}/ttp-test.XXXXXX") || exit 1
cleanup() {
    GNUPGHOME=$tmp/gnupg gpgconf --kill gpg-agent > /dev/null 2>&1
    rm -rf "$tmp"
}
trap cleanup EXIT

########################################################################
# Unit tests: source ttp and call its functions directly.

# shellcheck source=/dev/null
source "$ttp"

echo "Testing sha1"
hash_in=()
sha1
check "sha1 of empty string" da39a3ee5e6b4b0d3255bfef95601890afd80709 "$(hex "${hash_out[@]}")"
to_bytes abc
hash_in=("${bytes[@]}")
sha1
check "sha1 of abc" a9993e364706816aba3e25717850c26c9cd0d89d "$(hex "${hash_out[@]}")"
to_bytes abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq
hash_in=("${bytes[@]}")
sha1
check "sha1 of 56-byte string" 84983e441c3bd26ebaae4aa1f95129e5e54670f1 "$(hex "${hash_out[@]}")"

echo "Testing sha256 and sha512"
hash_in=()
sha256
check "sha256 of empty string" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "$(hex "${hash_out[@]}")"
sha512
check "sha512 of empty string" cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e "$(hex "${hash_out[@]}")"
to_bytes abc
hash_in=("${bytes[@]}")
sha256
check "sha256 of abc" ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad "$(hex "${hash_out[@]}")"
sha512
check "sha512 of abc" ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f "$(hex "${hash_out[@]}")"
to_bytes abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq
hash_in=("${bytes[@]}")
sha256
check "sha256 of 56-byte string" 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 "$(hex "${hash_out[@]}")"

# Compare against the system's hash tools across the padding boundaries
# of both 64-byte (SHA-1, SHA-256) and 128-byte (SHA-512) blocks.
for bits in 1 256 512; do
    if command -v "sha${bits}sum" > /dev/null; then
        tool=("sha${bits}sum")
    elif command -v shasum > /dev/null; then
        tool=(shasum -a "$bits")
    else
        echo "  (no sha${bits}sum or shasum found; skipping comparison)"
        continue
    fi
    for len in 1 54 55 56 57 63 64 65 111 112 113 119 120 127 128 129 200 240; do
        hash_in=()
        escapes=
        for ((i = 0; i < len; i++)); do
            hash_in+=($(( (i * 37 + len) & 255 )))
            escapes+=$(printf '\\%03o' $(( (i * 37 + len) & 255 )))
        done
        # shellcheck disable=SC2059
        printf "$escapes" > "$tmp/blob"
        "sha$bits"
        want=$("${tool[@]}" < "$tmp/blob")
        check "sha$bits of $len bytes matches ${tool[*]}" "${want%% *}" "$(hex "${hash_out[@]}")"
    done
done

echo "Testing hmac sha1 (RFC 2202 test cases)"
repeat_byte 11 20
hmac_key=("${bytes[@]}")
to_bytes "Hi There"
hmac_msg=("${bytes[@]}")
hmac sha1
check "RFC 2202 case 1" b617318655057264e28bc0b6fb378c8ef146be00 "$(hex "${hash_out[@]}")"

to_bytes Jefe
hmac_key=("${bytes[@]}")
to_bytes "what do ya want for nothing?"
hmac_msg=("${bytes[@]}")
hmac sha1
check "RFC 2202 case 2" effcdf6ae5eb2fa2d27416d5f184df9c259a7c79 "$(hex "${hash_out[@]}")"

repeat_byte 170 20
hmac_key=("${bytes[@]}")
repeat_byte 221 50
hmac_msg=("${bytes[@]}")
hmac sha1
check "RFC 2202 case 3" 125d7342b9ac11cd91a39af48aa17b4f63f175d3 "$(hex "${hash_out[@]}")"

repeat_byte 170 80
hmac_key=("${bytes[@]}")
to_bytes "Test Using Larger Than Block-Size Key - Hash Key First"
hmac_msg=("${bytes[@]}")
hmac sha1
check "RFC 2202 case 6 (key longer than a block)" aa4ae5e15272d00e95705637ce8a3b55ed402112 "$(hex "${hash_out[@]}")"

echo "Testing hmac sha256 and sha512 (RFC 4231 test cases)"
for alg in sha256 sha512; do
    repeat_byte 11 20
    hmac_key=("${bytes[@]}")
    to_bytes "Hi There"
    hmac_msg=("${bytes[@]}")
    hmac "$alg"
    case $alg in
        sha256) want=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 ;;
        sha512) want=87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854 ;;
    esac
    check "RFC 4231 case 1 ($alg)" "$want" "$(hex "${hash_out[@]}")"

    to_bytes Jefe
    hmac_key=("${bytes[@]}")
    to_bytes "what do ya want for nothing?"
    hmac_msg=("${bytes[@]}")
    hmac "$alg"
    case $alg in
        sha256) want=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 ;;
        sha512) want=164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737 ;;
    esac
    check "RFC 4231 case 2 ($alg)" "$want" "$(hex "${hash_out[@]}")"

    repeat_byte 170 20
    hmac_key=("${bytes[@]}")
    repeat_byte 221 50
    hmac_msg=("${bytes[@]}")
    hmac "$alg"
    case $alg in
        sha256) want=773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe ;;
        sha512) want=fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb ;;
    esac
    check "RFC 4231 case 3 ($alg)" "$want" "$(hex "${hash_out[@]}")"

    # A key longer than even SHA-512's 128-byte block.
    repeat_byte 170 131
    hmac_key=("${bytes[@]}")
    to_bytes "Test Using Larger Than Block-Size Key - Hash Key First"
    hmac_msg=("${bytes[@]}")
    hmac "$alg"
    case $alg in
        sha256) want=60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54 ;;
        sha512) want=80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598 ;;
    esac
    check "RFC 4231 case 6 ($alg, key longer than a block)" "$want" "$(hex "${hash_out[@]}")"
done

echo "Testing totp"
# The RFC 4226 and RFC 6238 test key, "12345678901234567890", in base32.
key=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ

# RFC 6238 appendix B (SHA1, 8 digits).
for vector in 59:94287082 1111111109:07081804 1111111111:14050471 \
              1234567890:89005924 2000000000:69279037 20000000000:65353130; do
    time=${vector%%:*}
    check "RFC 6238 at time $time" "${vector#*:}" \
        "$(echo "otpauth://totp/test?secret=$key&digits=8" | totp "$time")"
done

# RFC 6238 appendix B with SHA-256 and SHA-512, whose test keys are the
# same digits repeated to 32 and 64 bytes.
key256=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA
key512=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA
for vector in 59:46119246 1111111109:68084774 1111111111:67062674 1234567890:91819424 2000000000:90698825 20000000000:77737706; do
    time=${vector%%:*}
    check "RFC 6238 SHA256 at time $time" "${vector#*:}" \
        "$(echo "otpauth://totp/test?secret=$key256&digits=8&algorithm=SHA256" | totp "$time")"
done
for vector in 59:90693936 1111111109:25091201 1111111111:99943326 1234567890:93441116 2000000000:38618901 20000000000:47863826; do
    time=${vector%%:*}
    check "RFC 6238 SHA512 at time $time" "${vector#*:}" \
        "$(echo "otpauth://totp/test?secret=$key512&digits=8&algorithm=SHA512" | totp "$time")"
done

# RFC 4226 appendix D (6 digits); counter c is time c * 30.
counter=0
for want in 755224 287082 359152 969429 338314 254676 287922 162583 399871 520489; do
    check "RFC 4226 counter $counter" "$want" "$(echo "$key" | totp $((counter * 30)))"
    counter=$((counter + 1))
done

check "lowercase key" 287082 "$(echo "$key" | tr '[:upper:]' '[:lower:]' | totp 30)"
check "key with spaces and tabs" 287082 "$(printf 'GEZD GNBV\tGY3T QOJQ GEZDGNBVGY3TQOJQ\n' | totp 30)"
check "padded key" "$(echo MZXW6 | totp 30)" "$(echo 'MZXW6===' | totp 30)"
check "URI with secret first" 287082 "$(echo "otpauth://totp/a:b?secret=$key&issuer=a" | totp 30)"
check "URI with secret last" 287082 "$(echo "otpauth://totp/a:b?issuer=a&secret=$key" | totp 30)"
check "URI with SHA1 algorithm" 287082 "$(echo "otpauth://totp/a?secret=$key&algorithm=SHA1" | totp 30)"
check "URI with 60 second period" 359152 "$(echo "otpauth://totp/a?secret=$key&period=60" | totp 120)"
check "URI with a key line and no newline" 287082 "$(printf '%s' "$key" | totp 30)"

# expect_error NAME MESSAGE INPUT
expect_error() {
    local out rc
    out=$(printf '%s' "$3" | totp 30 2>&1)
    rc=$?
    check "$1: exit status" 1 "$rc"
    check_contains "$1: message" "$2" "$out"
}
expect_error "empty input" "aborted" ""
expect_error "invalid character" "bad key" $'ABC!EFGH\n'
expect_error "invalid length" "bad key" $'A\n'
expect_error "URI without secret" "bad key" $'otpauth://totp/a?issuer=a\n'
expect_error "URI without query" "bad key" $'otpauth://totp/a\n'
expect_error "HOTP URI" "bad key" "otpauth://hotp/a?secret=$key&counter=1"$'\n'
expect_error "MD5 URI" "unsupported algorithm" "otpauth://totp/a?secret=$key&algorithm=MD5"$'\n'
expect_error "zero digits" "unsupported number of digits" "otpauth://totp/a?secret=$key&digits=0"$'\n'
expect_error "11 digits" "unsupported number of digits" "otpauth://totp/a?secret=$key&digits=11"$'\n'
expect_error "zero period" "unsupported period" "otpauth://totp/a?secret=$key&period=0"$'\n'
expect_error "non-numeric period" "unsupported period" "otpauth://totp/a?secret=$key&period=x"$'\n'

# Bash arithmetic evaluates command substitutions in array subscripts,
# so make sure URI parameters never reach it unchecked.
for param in digits period; do
    rm -f "$tmp/pwned"
    expect_error "code in $param" "unsupported" \
        "otpauth://totp/a?secret=$key&$param=a[\$(touch $tmp/pwned)]"$'\n'
    check "code in $param is not run" no "$(test -e "$tmp/pwned" && echo yes || echo no)"
done

echo "Testing qr_uris and gk (choosing a QR code from zbarimg output)"
qr_a="otpauth://totp/A:alice?secret=$key&issuer=A"
qr_b="otpauth://totp/B:bob?secret=MZXW6YTBOI&issuer=B"
qr_lines=$(printf 'QR-Code:https://example.com\nQR-Code:%s\nQR-Code:%s\n' "$qr_a" "$qr_b")

# choose ANSWERS: run gk on $qr_lines, answering its questions with
# ANSWERS (with \n escapes), setting $chosen and $prompts.
choose() {
    printf '%b' "$1" > "$tmp/answers"
    chosen=$(qr_uris <<< "$qr_lines" | ttydev=$tmp/answers gk 2> "$tmp/prompts")
    prompts=$(cat "$tmp/prompts")
}
choose '\n'
check "gk: empty answer picks the first code" "$qr_a" "$chosen"
check "gk: asks only about TOTP codes" "Use A:alice? (y) " "$prompts"
choose 'y\n'
check "gk: y picks the first code" "$qr_a" "$chosen"
choose 'yes\n'
check "gk: yes picks the first code" "$qr_a" "$chosen"
choose 'n\ny\n'
check "gk: n then y picks the second code" "$qr_b" "$chosen"
check "gk: asks about each code in turn" "Use A:alice? (y) Use B:bob? (y) " "$prompts"
choose 'n\nn\n'
check "gk: declining every code picks none" "" "$chosen"

echo "Testing Google Authenticator export decoding"
check "base32_encode of the RFC key" "$key" "$(base32_encode 49 50 51 52 53 54 55 56 57 48 49 50 51 52 53 54 55 56 57 48)"
check "base32_encode of foo" MZXW6 "$(base32_encode 102 111 111)"
check "base32_encode of nothing" "" "$(base32_encode)"
check "base32_encode of 00 ff 10" AD7RA "$(base32_encode 0 255 16)"
to_bytes "Zo"
check "uri_encode of UTF-8, space and &" "Zo%C3%AB%20%26%20co" "$(uri_encode "${bytes[@]}" 195 171 32 38 32 99 111)"
to_bytes "a-._~:@Z9"
check "uri_encode keeps unreserved characters" "a-._~:@Z9" "$(uri_encode "${bytes[@]}")"

# Exports built independently, by hand-encoding the protobuf in Python:
# two holds alice (Example, SHA1, 6 digits) and bob (no issuer, 8
# digits); mixed holds an HOTP key, a SHA256 key, a name that already
# starts with its issuer, and a non-ASCII name with a space and "&".
export_two='otpauth-migration://offline?data=CjgKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhFhbGljZUBleGFtcGxlLmNvbRoHRXhhbXBsZSABKAEwAgoTCgZmb29iYXISA2JvYiAAKAIwAhABGAEgACiVmu86'
export_two_raw='otpauth-migration://offline?data=CjgKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhFhbGljZUBleGFtcGxlLmNvbRoHRXhhbXBsZSABKAEwAgoTCgZmb29iYXISA2JvYiAAKAIwAhABGAEgACiVmu86'
export_mixed='otpauth-migration://offline?data=Ch0KCmhvdHBzZWNyZXQSB2NvdW50ZXIgASgBMAE4BQonCgpzaGFzZWNyZXQhEgtzaGEyNTYgdXNlchoGQmlnIENvIAIoATACCikKCUV4YW1wbGU6eBINRXhhbXBsZTpjYXJvbBoHRXhhbXBsZSABKAEwAgoWCgMA%2FxASCVpvw6sgJiBjbyABKAEwAhABGAEgACiVmu86'
uri_alice="otpauth://totp/Example:alice@example.com?secret=$key&issuer=Example"
uri_bob="otpauth://totp/bob?secret=MZXW6YTBOI&digits=8"
check "export with two keys" "$uri_alice"$'\n'"$uri_bob" "$(migration_uris "$export_two")"
check "export without URI encoding" "$uri_alice"$'\n'"$uri_bob" "$(migration_uris "$export_two_raw")"
out=$(migration_uris "$export_mixed" 2> "$tmp/stderr")
check "export with mixed keys" \
    "otpauth://totp/Big%20Co:sha256%20user?secret=ONUGC43FMNZGK5BB&issuer=Big%20Co&algorithm=SHA256
otpauth://totp/Example:carol?secret=IV4GC3LQNRSTU6A&issuer=Example
otpauth://totp/Zo%C3%AB%20%26%20co?secret=AD7RA" "$out"
check_contains "export with an HOTP key: skipped" "skipping counter: counter-based (HOTP)" "$(cat "$tmp/stderr")"
check "SHA256 key from an export" 848978 "$(printf '%s\n' "$out" | sed -n 1p | totp 30)"
check "8-digit key from an export" 8 "$(echo "$uri_bob" | totp 30 | tr -d '\n' | wc -c | tr -d ' ')"

# expect_bad_export NAME URI
expect_bad_export() {
    local out rc
    out=$(migration_uris "$2" 2>&1)
    rc=$?
    check "$1: exit status" 1 "$rc"
    check_contains "$1: message" "bad Google Authenticator export" "$out"
}
expect_bad_export "export with invalid base64" "otpauth-migration://offline?data=ab!d"
expect_bad_export "truncated export" "${export_two_raw:0:60}"
expect_bad_export "export with a bad wire type" "otpauth-migration://offline?data=Dw"
check "empty export" "" "$(migration_uris "otpauth-migration://offline?data=" 2>&1)"
check "qr_uris expands exports among other codes" \
    "otpauth://totp/A?secret=$key"$'\n'"$uri_alice"$'\n'"$uri_bob" \
    "$(printf 'QR-Code:https://example.com\nQR-Code:otpauth://totp/A?secret=%s\nQR-Code:%s\n' "$key" "$export_two" | qr_uris)"

########################################################################
# Command-line tests: run ttp as a program, with gpg wrapped to use a
# fixed passphrase and no prompts.

echo "Testing the ttp command"
real_gpg=$(command -v gpg) || { echo "gpg is required"; exit 1; }
mkdir -p "$tmp/bin" "$tmp/failbin" "$tmp/gnupg" "$tmp/config"
chmod 700 "$tmp/gnupg"
# Weak defaults, so the tests show that ttp asks for strong encryption
# itself rather than relying on gpg's defaults.
cat > "$tmp/gnupg/gpg.conf" <<'EOF'
cipher-algo AES128
s2k-cipher-algo AES128
s2k-digest-algo SHA1
s2k-count 1024
EOF
# gpg takes the default iteration count from gpg-agent.
echo "s2k-count 1024" > "$tmp/gnupg/gpg-agent.conf"
cat > "$tmp/bin/gpg" <<EOF
#!/bin/sh
exec "$real_gpg" --batch --passphrase test-passphrase "\$@"
EOF
# qrencode stand-in that prints what it would encode.
cat > "$tmp/bin/qrencode" <<'EOF'
#!/bin/sh
cat
echo
EOF
# gpg stand-in that always fails.
printf '#!/bin/sh\nexit 2\n' > "$tmp/failbin/gpg"
chmod +x "$tmp/bin/gpg" "$tmp/bin/qrencode" "$tmp/failbin/gpg"

export PATH="$tmp/bin:$PATH" GNUPGHOME="$tmp/gnupg" XDG_CONFIG_HOME="$tmp/config"
unset DISPLAY WAYLAND_DISPLAY

# run ARGS...: run ttp, setting $out and $rc.
run() {
    out=$("$BASH" "$ttp" "$@" 2>&1)
    rc=$?
}

run -xc demo <<< "$key"
check "-xc: exit status" 0 "$rc"
check "-xc: key file created" yes "$(test -f "$tmp/config/ttp/demo.gpg" && echo yes)"
# ls is the portable way to read permissions; stat differs across systems.
# shellcheck disable=SC2012
check "-xc: key file is private" "-rw-------" "$(ls -l "$tmp/config/ttp/demo.gpg" | cut -c1-10)"
packets=$("$real_gpg" --batch --pinentry-mode loopback --passphrase test-passphrase \
    --list-packets "$tmp/config/ttp/demo.gpg" 2>&1)
check_contains "-xc: key encrypted with AES-256" "cipher 9," "$packets"
check_contains "-xc: passphrase hashed with SHA-512" "hash 10" "$packets"
check_contains "-xc: passphrase hashed the most times gpg allows" "count 65011712" "$packets"

# main lowers the core dump limit, if the system lets the test raise it.
if ulimit -c unlimited 2> /dev/null; then
    check "core dumps disabled" 0 \
        "$(ulimit -c unlimited; keydir=$tmp/config/ttp main -l > /dev/null; ulimit -c)"
fi

run -l
check "-l: lists keys" demo "$out"

# The code depends on the current time, so accept the code from just
# before or just after running ttp.
before=$(echo "$key" | totp)
run -x demo
after=$(echo "$key" | totp)
check "-x: exit status" 0 "$rc"
check "-x: prints current code" yes \
    "$(test "$out" = "$before" -o "$out" = "$after" && echo yes || echo "no ($out)")"

run -xc demo <<< "$key"
check "-xc existing key: exit status" 1 "$rc"
check_contains "-xc existing key: message" "exists already" "$out"

run -x nosuch
check "-x unknown service: exit status" 1 "$rc"
check_contains "-x unknown service: message" "no key for nosuch" "$out"

run -xv nosuch
check "-xv unknown service: exit status" 1 "$rc"

for args in "" "-c" "-x" "a b c"; do
    run $args
    check "usage for '$args': exit status" 1 "$rc"
    check_contains "usage for '$args': message" "usage:" "$out"
done

run -xc empty <<< ""
check "-xc with no key: exit status" 0 "$rc"
check_contains "-xc with no key: message" "Aborted." "$out"
check "-xc with no key: no file" no "$(test -e "$tmp/config/ttp/empty.gpg" && echo yes || echo no)"

run -xc bad <<< "NOT!VALID"
check "-xc with bad key: exit status" 1 "$rc"
check "-xc with bad key: no file" no "$(test -e "$tmp/config/ttp/bad.gpg" && echo yes || echo no)"

out=$(PATH="$tmp/failbin:$PATH" "$BASH" "$ttp" -xc broken <<< "$key" 2>&1)
check "-xc when gpg fails: exit status" 1 "$?"

for name in ../escape a/b .hidden -dash; do
    for mode in -xc -x -xv; do
        run $mode "$name" <<< "$key"
        check "$mode '$name': exit status" 1 "$rc"
        # With -x, a lone "-dash" argument is rejected as an unknown option.
        case "$mode $name" in
            "-x -dash") want="usage:" ;;
            *) want="invalid service name" ;;
        esac
        check_contains "$mode '$name': message" "$want" "$out"
    done
done
check "invalid names: no files written" "demo.gpg" "$(cd "$tmp/config/ttp" && echo *)"
check "invalid names: nothing outside the key directory" no \
    "$(test -e "$tmp/config/escape.gpg" && echo yes || echo no)"

run -xc "my bank" <<< "$key"
check "-xc name with a space: exit status" 0 "$rc"
run -x "my bank"
check "-x name with a space: exit status" 0 "$rc"
rm -f "$tmp/config/ttp/my bank.gpg"

# -c reading a QR code from the screen.  ttp's functions were sourced
# above, so call main directly, in a subshell, with a stand-in zbarimg
# that "sees" $tmp/screen, and with keydir pointed at the test's key
# directory.
cat > "$tmp/bin/zbarimg" <<EOF
#!/bin/sh
cat "$tmp/screen"
EOF
chmod +x "$tmp/bin/zbarimg"

# scan NAME ANSWERS: run "ttp -c NAME" with ANSWERS (with \n escapes)
# as the terminal input, setting $out and $rc.
scan() {
    printf '%b' "$2" > "$tmp/answers"
    out=$(keydir=$tmp/config/ttp ttydev=$tmp/answers DISPLAY=:0 main -c "$1" 2>&1)
    rc=$?
}

printf '%s\n' "$qr_lines" > "$tmp/screen"
scan scanned 'n\ny\n' < /dev/null
check "-c from screen: exit status" 0 "$rc"
check_contains "-c from screen: asks which code" "Use B:bob? (y)" "$out"
run -xv scanned
check "-c from screen: stores the chosen URI" "$qr_b" "$out"

scan declined 'n\nn\n' < /dev/null
check "-c declining every code: exit status" 0 "$rc"
check_contains "-c declining every code: asks for a key" "Enter Base32-encoded authenticator key" "$out"
check "-c declining every code: no file" no "$(test -e "$tmp/config/ttp/declined.gpg" && echo yes || echo no)"

: > "$tmp/screen"
scan typed '' <<< "$key"
check "-c with no QR code: exit status" 0 "$rc"
run -xv typed
check "-c with no QR code: stores the typed key" "otpauth://totp/typed?secret=$key&issuer=typed" "$out"
# A Google Authenticator export on screen: pick bob, the second key.
printf 'QR-Code:%s\n' "$export_two" > "$tmp/screen"
scan exported 'n\ny\n' < /dev/null
check "-c from an export on screen: exit status" 0 "$rc"
check_contains "-c from an export on screen: asks about alice" "Use Example:alice@example.com? (y)" "$out"
run -xv exported
check "-c from an export on screen: stores the chosen key" "$uri_bob" "$out"
run -x exported
check "-x with a key from an export: 8 digits" 8 "${#out}"

# A pasted export URI: pick alice, the first key.
: > "$tmp/screen"
scan pasted 'y\n' <<< "$export_two"
check "-c with a pasted export: exit status" 0 "$rc"
run -xv pasted
check "-c with a pasted export: stores the chosen key" "$uri_alice" "$out"

scan none 'n\nn\n' <<< "$export_two"
check "-c declining every key in a pasted export: exit status" 0 "$rc"
check_contains "-c declining every key in a pasted export: message" "Aborted." "$out"
check "-c declining every key in a pasted export: no file" no \
    "$(test -e "$tmp/config/ttp/none.gpg" && echo yes || echo no)"
rm -f "$tmp/bin/zbarimg" "$tmp/config/ttp/scanned.gpg" "$tmp/config/ttp/typed.gpg" \
    "$tmp/config/ttp/exported.gpg" "$tmp/config/ttp/pasted.gpg"

# Clipboard tools.  Each stand-in records its arguments and input.
mkdir -p "$tmp/clipbin"
for tool in wl-copy xclip xsel; do
    cat > "$tmp/clipbin/$tool" <<EOF
#!/bin/sh
echo "$tool \$*" > "$tmp/clip"
cat >> "$tmp/clip"
EOF
    chmod +x "$tmp/clipbin/$tool"
done

# clip ENV...: get a code without -x, with the given environment and the
# stand-in clipboard tools first on PATH, setting $out, $rc and $clip.
clip() {
    rm -f "$tmp/clip"
    out=$(env PATH="$tmp/clipbin:$PATH" "$@" "$BASH" "$ttp" demo 2>&1)
    rc=$?
    clip=$(cat "$tmp/clip" 2>/dev/null)
}
before=$(echo "$key" | totp)
clip WAYLAND_DISPLAY=wayland-0 DISPLAY=:0
after=$(echo "$key" | totp)
copied=${clip#*$'\n'}
check "Wayland: exit status" 0 "$rc"
check "Wayland: message" "Sending code to Wayland clipboard" "$out"
check "Wayland: uses wl-copy" "wl-copy " "${clip%%$'\n'*}"
check "Wayland: copies the code" yes \
    "$(test "$copied" = "$before" -o "$copied" = "$after" && echo yes || echo "no ($copied)")"

clip DISPLAY=:0
check "X11: message" "Sending code to X clipboard" "$out"
check "X11: xclip uses the Ctrl-V clipboard" "xclip -selection clipboard -i" "${clip%%$'\n'*}"

rm "$tmp/clipbin/xclip"
clip DISPLAY=:0
check "X11 without xclip: xsel uses the Ctrl-V clipboard" "xsel --clipboard --input" "${clip%%$'\n'*}"

rm -f "$tmp/clip"
out=$(env PATH="$tmp/clipbin:$PATH" WAYLAND_DISPLAY=wayland-0 DISPLAY=:0 "$BASH" "$ttp" -x demo 2>&1)
check "-x with Wayland and X11: prints the code" 6 "${#out}"
check "-x with Wayland and X11: no clipboard" no "$(test -e "$tmp/clip" && echo yes || echo no)"

# pbcopy is used last, so only test it when no real xclip or xsel is
# installed to take precedence.
if ! command -v xclip > /dev/null && ! command -v xsel > /dev/null; then
    mkdir -p "$tmp/macbin"
    cat > "$tmp/macbin/pbcopy" <<EOF
#!/bin/sh
echo "pbcopy \$*" > "$tmp/clip"
cat >> "$tmp/clip"
EOF
    chmod +x "$tmp/macbin/pbcopy"
    rm -f "$tmp/clip"
    out=$(env PATH="$tmp/macbin:$PATH" DISPLAY=:0 "$BASH" "$ttp" demo 2>&1)
    check "pbcopy: message" "Sending code to OSX clipboard" "$out"
    check "pbcopy: copies a code" 6 "$(sed -n 2p "$tmp/clip" | tr -d '\n' | wc -c | tr -d ' ')"
fi

# QR code viewers, in order of preference.  qrencode -o- would write a
# PNG; the stand-in writes the URI, and each viewer records what it got.
mkdir -p "$tmp/viewbin"
for viewer in display xv xloadimage; do
    cat > "$tmp/viewbin/$viewer" <<EOF
#!/bin/sh
echo "$viewer \$*" > "$tmp/view"
cat >> "$tmp/view"
EOF
    chmod +x "$tmp/viewbin/$viewer"
done
# A real viewer later in the order would take over once a stand-in is
# removed, so only test the fallbacks when none is installed.
if command -v display xv xloadimage > /dev/null; then
    viewers=display
else
    viewers="display xv xloadimage"
fi
for viewer in $viewers; do
    rm -f "$tmp/view"
    out=$(env PATH="$tmp/viewbin:$PATH" DISPLAY=:0 "$BASH" "$ttp" -v demo 2>&1)
    case $viewer in
        xloadimage) want="xloadimage stdin" ;;
        *) want="$viewer -" ;;
    esac
    check "-v with $viewer: viewer and arguments" "$want" "$(sed -n 1p "$tmp/view" 2>/dev/null)"
    check "-v with $viewer: URI" "otpauth://totp/demo?secret=$key&issuer=demo" "$(sed -n 2p "$tmp/view" 2>/dev/null)"
    rm "$tmp/viewbin/$viewer"
done
if test "$viewers" != display; then
    out=$(env PATH="$tmp/viewbin:$PATH" DISPLAY=:0 "$BASH" "$ttp" -v demo 2>&1)
    check "-v with no viewer: drawn in the terminal" "otpauth://totp/demo?secret=$key&issuer=demo" "$out"
else
    echo "  (a QR code viewer is installed; skipping the viewer fallback tests)"
fi

# The GNOME keyring warning.
mkdir -p "$tmp/gnomebin"
for method in idle session; do
    printf '#!/bin/sh\necho "'"'"'%s'"'"'"\n' "$method" > "$tmp/gnomebin/gsettings"
    chmod +x "$tmp/gnomebin/gsettings"
    out=$(env PATH="$tmp/gnomebin:$PATH" "$BASH" "$ttp" -l 2>&1)
    case $method in
        idle) check "gsettings idle: no warning" demo "$out" ;;
        *) check_contains "gsettings $method: warning" "WARNING:  gnome-keyring-daemon" "$out" ;;
    esac
done

# A wrong passphrase gives an error, not a code.
cat > "$tmp/failbin/gpg" <<EOF
#!/bin/sh
exec "$real_gpg" --batch --passphrase wrong-passphrase "\$@"
EOF
out=$(PATH="$tmp/failbin:$PATH" "$BASH" "$ttp" -x demo 2>&1)
rc=$?
check "wrong passphrase: exit status" 1 "$rc"
case "$out" in
    *[0-9][0-9][0-9][0-9][0-9][0-9]*) fail "wrong passphrase: printed something like a code" "$out" ;;
esac

uri="otpauth://totp/Example%3Aalice%40example.com?secret=$key&issuer=Example&digits=8"
run -xc eight <<< "$uri"
check "-xc with URI: exit status" 0 "$rc"
run -x eight
check "-x with 8-digit URI: length" 8 "${#out}"

run -xv eight
check "-xv with URI: prints URI unchanged" "$uri" "$out"
run -xv demo
check "-xv with plain key: builds URI" "otpauth://totp/demo?secret=$key&issuer=demo" "$out"

########################################################################
# Cross-check against oathtool, an independent TOTP implementation, when
# it is installed.

if command -v oathtool > /dev/null; then
    echo "Comparing with oathtool"
    for ((n = 0; n < 50; n++)); do
        len=$(( (RANDOM % 8 + 1) * 8 ))
        secret=
        for ((i = 0; i < len; i++)); do
            secret+=${b32chars:RANDOM % 32:1}
        done
        time=$(( RANDOM * RANDOM ))
        case $(( n % 3 )) in
            0) digits=6 period=30 ;;
            1) digits=8 period=30 ;;
            2) digits=6 period=60 ;;
        esac
        case $(( n % 4 )) in
            0|1) algorithm=SHA1 ;;
            2) algorithm=SHA256 ;;
            3) algorithm=SHA512 ;;
        esac
        want=$(oathtool --totp="$algorithm" -b -d "$digits" -s "${period}s" -N "@$time" "$secret")
        got=$(echo "otpauth://totp/x?secret=$secret&digits=$digits&period=$period&algorithm=$algorithm" | totp "$time")
        check "oathtool: $secret, $algorithm, digits=$digits, period=$period, time=$time" "$want" "$got"
    done
else
    echo "  (oathtool not found; skipping comparison)"
fi

########################################################################

echo
echo "bash $BASH_VERSION: $((tests - failures)) of $tests checks passed"
test "$failures" -eq 0
