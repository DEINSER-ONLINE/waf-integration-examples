<?php

/**
 * Deinser WAF - Integration script to send logs and check blocked IPs.
 * Define before the require: define('DEINSER_WAF_TOKEN', 'your-web-account-token');
 * Optional: define('DEINSER_WAF_REALTIME', 1); to evaluate blocking with check-request if the IP is not in the local list.
 * Include at the beginning of the project/framework: require_once __DIR__ . '/deinser-waf.php';
 */

$DEINSER_WAF_ENDPOINT = 'https://waf.deinser.com';
$DEINSER_WAF_INTEGRATION_VERSION = '1.0.0';
$DEINSER_WAF_IP_FILENAME = '.deinser-waf-ips';

try {
    if (defined('DEINSER_WAF_TOKEN')) {
        execute_deinser_waf();
    }
} catch (Throwable $e) {
    // If any error occurs, the execution of the rest of the PHP continues without problems.
}

function execute_deinser_waf(): void
{
    global $DEINSER_WAF_ENDPOINT, $DEINSER_WAF_INTEGRATION_VERSION, $DEINSER_WAF_IP_FILENAME;

    $token = DEINSER_WAF_TOKEN;

    $isDownload = (
        ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
        && isset($_POST['deinser_download_waf_ips']) && $_POST['deinser_download_waf_ips'] == '1'
        && isset($_POST['token']) && $_POST['token'] === $token
    );

    $userAgent = 'DEINSER_WAF_INTEGRATION-' . $DEINSER_WAF_INTEGRATION_VERSION;

    if ($isDownload) {
        deinser_download_blocked_ips($DEINSER_WAF_ENDPOINT, $DEINSER_WAF_IP_FILENAME, $token, $userAgent);
        return;
    } else {
        deinser_log_request($DEINSER_WAF_ENDPOINT, $DEINSER_WAF_IP_FILENAME, $token, $userAgent);
    }
}

function deinser_download_blocked_ips(string $endpoint, string $ipFilename, string $token, string $userAgent): void
{
    $url = rtrim($endpoint, '/') . '/api/blocked-ips?one-line=1';

    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "X-TOKEN: {$token}\r\nUser-Agent: {$userAgent}\r\n",
            'timeout' => 30,
        ],
    ]);

    $content = @file_get_contents($url, false, $ctx);
    if ($content !== false) {
        file_put_contents($ipFilename, $content);
    }
}

function deinser_get_client_ip(): string
{
    if (! empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return trim($_SERVER['HTTP_CF_CONNECTING_IP']);
    }
    if (! empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $list = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($list[0]);
        if ($ip !== '') {
            return $ip;
        }
    }
    if (! empty($_SERVER['HTTP_X_REAL_IP'])) {
        return trim($_SERVER['HTTP_X_REAL_IP']);
    }
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
}

function deinser_ip_is_blocked(string $ipFilename, string $ip): bool
{
    if ($ip === '' || ! is_file($ipFilename) || ! is_readable($ipFilename)) {
        return false;
    }

    $ipEsc = preg_quote($ip, '/');
    // IP as a complete word: between start/comma and comma/end (one-line format: ip1,ip2,...)
    $pattern = '/(^|,)' . $ipEsc . '(,|$)/';

    $chunkSize = 65536;
    $overlap = 50; // suficiente para cualquier IPv4/IPv6
    $handle = fopen($ipFilename, 'rb');
    if (! $handle) {
        return false;
    }

    $suffix = '';
    while (! feof($handle)) {
        $chunk = fread($handle, $chunkSize);
        if ($chunk === false) {
            break;
        }
        $block = $suffix . $chunk;
        if (preg_match($pattern, $block)) {
            fclose($handle);
            return true;
        }
        $suffix = $overlap >= strlen($block) ? $block : substr($block, -$overlap);
    }
    fclose($handle);
    // Last chunk if the IP is at the end
    if ($suffix !== '' && preg_match($pattern, $suffix)) {
        return true;
    }
    return false;
}

function deinser_log_request(string $endpoint, string $ipFilename, string $token, string $userAgent): void
{
    $ip = deinser_get_client_ip();
    $path = $_SERVER['REQUEST_URI'] ?? '/';
    if (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING'] !== '' && strpos($path, '?') === false) {
        $path .= '?' . $_SERVER['QUERY_STRING'];
    }
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $type = isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] !== '' ? (string) $_SERVER['REQUEST_METHOD'] : null;
    $referrer = isset($_SERVER['HTTP_REFERER']) && $_SERVER['HTTP_REFERER'] !== '' ? (string) $_SERVER['HTTP_REFERER'] : null;

    // 1) Look up the local list of blocked IPs
    $blocked = deinser_ip_is_blocked($ipFilename, $ip);

    if (!$blocked) {
        // 2) Not in the list: if REALTIME is active, consult check-request; if not, allow
        $useRealtime = defined('DEINSER_WAF_REALTIME') && (int) DEINSER_WAF_REALTIME === 1;

        if ($useRealtime) {
            $response = deinser_check_request_sync($endpoint, $token, $userAgent, $ip, $path, $ua);
            $blocked = ($response !== null && isset($response['allowed']) && $response['allowed'] === false);
        } else {
            $blocked = false;
        }
    }

    deinser_fire_and_forget_log($endpoint, $token, $userAgent, $ip, $path, $ua, $blocked, $type, $referrer);

    if ($blocked) {
        print_deinser_waf_blocked_html($ip);
        http_response_code(403);
        exit;
    }
}

function print_deinser_waf_blocked_html(string $ip): void
{
    $html = <<<EOF
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Access Denied | DEINSER WAF</title>
            <style>
                * { box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    background: #f4f4f5;
                    color: #18181b;
                    margin: 0;
                    padding: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .page {
                    width: 100%;
                    max-width: 560px;
                    margin: 2rem;
                }
                .card {
                    background: #fff;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px -1px rgba(0,0,0,.08), 0 2px 4px -2px rgba(0,0,0,.06);
                    padding: 2.5rem 2rem;
                    text-align: center;
                }
                .logo {
                    display: block;
                    width: 120px;
                    height: auto;
                    margin: 0 auto 1.5rem;
                }
                .icon {
                    width: 72px;
                    height: 72px;
                    margin: 0 auto 1.25rem;
                    background: #fef2f2;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .icon svg {
                    width: 36px;
                    height: 36px;
                    color: #dc2626;
                }
                .title {
                    font-size: 1.5rem;
                    font-weight: 700;
                    color: #18181b;
                    margin: 0 0 0.5rem;
                }
                .subtitle {
                    font-size: 1rem;
                    color: #71717a;
                    margin: 0 0 1.5rem;
                    line-height: 1.5;
                }
                .details {
                    background: #fafafa;
                    border: 1px solid #e4e4e7;
                    border-radius: 8px;
                    padding: 1rem 1.25rem;
                    font-size: 0.875rem;
                    color: #71717a;
                    text-align: left;
                }
                .details dt { font-weight: 600; color: #3f3f46; margin-bottom: 0.25rem; }
                .details dd { margin: 0 0 0.75rem; font-family: ui-monospace, monospace; }
                .details dd:last-child { margin-bottom: 0; }
            </style>
        </head>
        <body>
            <div class="page">
                <div class="card">
                    <img src="https://waf.deinser.com/images/logo/logo_512.png" alt="DEINSER WAF" class="logo" width="120" height="120">
                    <div class="icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/></svg>
                    </div>
                    <h1 class="title">Access Denied</h1>
                    <p class="subtitle">Your request has been blocked by our security system. If you believe this is an error, please try again later or contact the site administrator.</p>
                    <dl class="details">
                        <dt>What happened?</dt>
                        <dd>This request was identified as potentially harmful and blocked.</dd>
                        <dt>Your IP address</dt>
                        <dd>{$ip}</dd>
                    </dl>
                </div>
            </div>
        </body>
        </html>
EOF;
    echo $html;
}

/**
 * Synchronous call to POST /api/check-request (ip, path, ua). Returns the decoded body or null if fails.
 */
function deinser_check_request_sync(
    string $endpoint,
    string $token,
    string $userAgent,
    string $ip,
    string $path,
    string $ua
): ?array {
    $url = rtrim($endpoint, '/') . '/api/check-request';
    $payload = [
        'ip' => $ip,
        'path' => strlen($path) > 1024 ? substr($path, 0, 1024) : $path,
        'ua' => $ua !== '' ? (strlen($ua) > 1024 ? substr($ua, 0, 1024) : $ua) : '',
    ];
    $body = json_encode($payload, JSON_UNESCAPED_UNICODE);

    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\nX-TOKEN: {$token}\r\nUser-Agent: {$userAgent}\r\n",
            'content' => $body,
            'timeout' => 1,
        ],
    ]);

    $responseBody = @file_get_contents($url, false, $ctx);
    if ($responseBody === false || $responseBody === '') {
        return null;
    }
    $decoded = json_decode($responseBody, true);
    return is_array($decoded) ? $decoded : null;
}

/**
 * Sends POST to /api/log-request. Waits up to 3s for the response to avoid
 * nginx registering 499 (client closed) and the server receiving and processing the body.
 */
function deinser_fire_and_forget_log(
    string $endpoint,
    string $token,
    string $userAgent,
    string $ip,
    string $path,
    string $ua,
    bool $blocked,
    ?string $type = null,
    ?string $referrer = null
): void {
    $url = rtrim($endpoint, '/') . '/api/log-request';
    $host = parse_url($url, PHP_URL_HOST);
    $port = parse_url($url, PHP_URL_PORT) ?: 443;
    $pathUri = parse_url($url, PHP_URL_PATH) ?: '/';
    $query = parse_url($url, PHP_URL_QUERY);
    if ($query) {
        $pathUri .= '?' . $query;
    }

    $payload = [
        'ip' => $ip,
        'path' => $path,
        'ua' => $ua,
        'blocked' => $blocked,
    ];
    if ($type !== null && $type !== '') {
        $payload['type'] = strlen($type) > 20 ? substr($type, 0, 20) : $type;
    }
    if ($referrer !== null && $referrer !== '') {
        $payload['referrer'] = strlen($referrer) > 1024 ? substr($referrer, 0, 1024) : $referrer;
    }
    $body = json_encode($payload, JSON_UNESCAPED_UNICODE);

    $request = "POST {$pathUri} HTTP/1.1\r\n";
    $request .= "Host: {$host}\r\n";
    $request .= "Content-Type: application/json\r\n";
    $request .= "X-TOKEN: {$token}\r\n";
    $request .= "User-Agent: {$userAgent}\r\n";
    $request .= 'Content-Length: ' . strlen($body) . "\r\n";
    $request .= "Connection: close\r\n\r\n";
    $request .= $body;

    $errno = 0;
    $errstr = '';
    $scheme = (parse_url($url, PHP_URL_SCHEME) === 'https') ? 'ssl://' : 'tcp://';
    $fp = @stream_socket_client(
        $scheme . $host . ':' . $port,
        $errno,
        $errstr,
        5,
        STREAM_CLIENT_CONNECT
    );
    if (! $fp) {
        return;
    }
    @stream_set_timeout($fp, 3);
    @fwrite($fp, $request);
    // Read the response (timeout 3s) so the server can respond 200/201 and not register 499.
    while (! feof($fp)) {
        $chunk = @fread($fp, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
    }
    @fclose($fp);
}
