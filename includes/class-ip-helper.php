<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_IP_Helper
{
    // Returns the client IP, honoring a trusted proxy header only when
    // the admin has explicitly opted in. Trusting proxy headers on a
    // directly-exposed site lets an attacker spoof their IP and bypass
    // brute force protection.
    public static function get_client_ip($trusted_proxy = 'none')
    {
        $remote = !empty($_SERVER['REMOTE_ADDR']) ? trim($_SERVER['REMOTE_ADDR']) : '';

        $header_value = '';
        switch ($trusted_proxy) {
            case 'cloudflare':
                if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
                    $header_value = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
                }
                break;
            case 'x-real-ip':
                if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
                    $header_value = trim($_SERVER['HTTP_X_REAL_IP']);
                }
                break;
            case 'x-forwarded-for':
                if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                    $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                    $header_value = trim($parts[0]);
                }
                break;
        }

        if ($header_value !== '' && filter_var($header_value, FILTER_VALIDATE_IP)) {
            return $header_value;
        }
        if ($remote !== '' && filter_var($remote, FILTER_VALIDATE_IP)) {
            return $remote;
        }
        return '';
    }

    public static function proxy_options()
    {
        return ['none', 'cloudflare', 'x-real-ip', 'x-forwarded-for'];
    }

    public static function is_whitelisted($ip, $whitelist_text)
    {
        if (empty($ip) || empty($whitelist_text)) {
            return false;
        }

        $lines = preg_split('/\r\n|\r|\n/', $whitelist_text);
        foreach ($lines as $line) {
            $entry = trim($line);
            if ($entry === '' || strpos($entry, '#') === 0) {
                continue;
            }
            if (strpos($entry, '/') !== false) {
                if (self::cidr_match($ip, $entry)) {
                    return true;
                }
            } elseif ($entry === $ip) {
                return true;
            }
        }
        return false;
    }

    public static function cidr_match($ip, $cidr)
    {
        list($subnet, $mask) = array_pad(explode('/', $cidr, 2), 2, null);
        if (!filter_var($subnet, FILTER_VALIDATE_IP) || !is_numeric($mask)) {
            return false;
        }
        $mask = (int) $mask;

        $is_v6_ip     = (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $is_v6_subnet = (bool) filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        if ($is_v6_ip !== $is_v6_subnet) {
            return false;
        }

        if ($is_v6_ip) {
            return self::cidr6_match($ip, $subnet, $mask);
        }
        return self::cidr4_match($ip, $subnet, $mask);
    }

    private static function cidr4_match($ip, $subnet, $mask)
    {
        if ($mask < 0 || $mask > 32) {
            return false;
        }
        $ip_long     = ip2long($ip);
        $subnet_long = ip2long($subnet);
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        if ($mask === 0) {
            return true;
        }
        $mask_long = -1 << (32 - $mask);
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }

    private static function cidr6_match($ip, $subnet, $mask)
    {
        if ($mask < 0 || $mask > 128) {
            return false;
        }
        $ip_bin     = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }
        $bytes = intdiv($mask, 8);
        $bits  = $mask % 8;
        if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($subnet_bin, 0, $bytes)) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        $mask_byte = chr(0xff << (8 - $bits) & 0xff);
        return (ord($ip_bin[$bytes]) & ord($mask_byte)) === (ord($subnet_bin[$bytes]) & ord($mask_byte));
    }
}
