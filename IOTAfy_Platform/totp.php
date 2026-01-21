<?php
// totp.php - Minimal TOTP helper (RFC 6238) with Base32 utilities
// No external dependencies.

if (!function_exists('base32_encode_nopad')) {
    function base32_encode_nopad(string $data): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $binary = '';
        foreach (str_split($data) as $char) {
            $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $chunks = str_split($binary, 5);
        $output = '';
        foreach ($chunks as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $output .= $alphabet[bindec($chunk)];
        }
        return $output; // no padding
    }
}

if (!function_exists('base32_decode')) {
    function base32_decode(string $base32): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $base32 = strtoupper(preg_replace('/[^A-Z2-7=]/', '', $base32));
        $binary = '';
        $padding = substr_count($base32, '=');
        $base32 = str_replace('=', '', $base32);
        $chars = str_split($base32);
        foreach ($chars as $c) {
            $pos = strpos($alphabet, $c);
            if ($pos === false) { continue; }
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $bytes = str_split($binary, 8);
        $output = '';
        foreach ($bytes as $byte) {
            if (strlen($byte) === 8) {
                $output .= chr(bindec($byte));
            }
        }
        return $output;
    }
}

if (!function_exists('totp_generate_secret')) {
    function totp_generate_secret(int $numBytes = 20): string {
        return base32_encode_nopad(random_bytes($numBytes));
    }
}

if (!function_exists('hotp')) {
    function hotp(string $secretBase32, int $counter, int $digits = 6, string $algo = 'sha1'): string {
        $secret = base32_decode($secretBase32);
        $binCounter = pack('J', $counter);
        // PHP on Windows may not support pack 'J' consistently; ensure 64-bit big-endian
        if (PHP_INT_SIZE < 8) {
            $high = ($counter & 0xFFFFFFFF00000000) >> 32;
            $low = $counter & 0xFFFFFFFF;
            $binCounter = pack('N2', $high, $low);
        } else {
            // Convert to big-endian if platform is little-endian
            $binCounter = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
        }
        $hash = hash_hmac($algo, $binCounter, $secret, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $truncated = (ord($hash[$offset]) & 0x7F) << 24
            | (ord($hash[$offset + 1]) & 0xFF) << 16
            | (ord($hash[$offset + 2]) & 0xFF) << 8
            | (ord($hash[$offset + 3]) & 0xFF);
        $code = $truncated % (10 ** $digits);
        return str_pad((string)$code, $digits, '0', STR_PAD_LEFT);
    }
}

if (!function_exists('totp_now')) {
    function totp_now(string $secretBase32, int $period = 30, int $digits = 6, string $algo = 'sha1', ?int $time = null): string {
        $time = $time ?? time();
        $counter = (int)floor($time / $period);
        return hotp($secretBase32, $counter, $digits, $algo);
    }
}

if (!function_exists('totp_verify')) {
    function totp_verify(string $secretBase32, string $code, int $period = 30, int $digits = 6, int $window = 1, string $algo = 'sha1', ?int $time = null): bool {
        $time = $time ?? time();
        $code = preg_replace('/\s+/', '', $code);
        if (!preg_match('/^\d{6}$/', $code)) {
            return false;
        }
        $counter = (int)floor($time / $period);
        for ($i = -$window; $i <= $window; $i++) {
            $calc = hotp($secretBase32, $counter + $i, $digits, $algo);
            if (hash_equals($calc, $code)) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('totp_build_otpauth_url')) {
    function totp_build_otpauth_url(string $secretBase32, string $accountLabel, string $issuer = 'IOTAfy', int $period = 30, int $digits = 6, string $algo = 'SHA1'): string {
        $label = rawurlencode($issuer . ':' . $accountLabel);
        $issuerParam = rawurlencode($issuer);
        $algo = strtoupper($algo);
        return "otpauth://totp/{$label}?secret={$secretBase32}&issuer={$issuerParam}&period={$period}&digits={$digits}&algorithm={$algo}";
    }
}
