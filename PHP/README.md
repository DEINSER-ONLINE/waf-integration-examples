# Deinser WAF Integration PHP (deinser-waf.php)

<p align="center">
  <img src="https://waf.deinser.com/images/logo/logo_256.png" width="256" alt="Deinser WAF Logo">
</p>

The `deinser-waf.php` script is used to integrate the WAF into a PHP application:

1. Define your token: `define('DEINSER_WAF_TOKEN', 'your-web-account-token');`
Optional: `define('DEINSER_WAF_REALTIME', 1);` to enable blocking evaluation with check-request if the IP is not in the local list. A Pro tier or higher is required.
2. Include it at the start of your code: `require_once __DIR__ . '/deinser-waf.php';`

Example of common `index.php` as starting app point:
```php
define('DEINSER_WAF_TOKEN', 'your-web-account-token');
// Optional: Enable real-time blocking evaluation (Pro tier or higher required)
// define('DEINSER_WAF_REALTIME', 1);

require_once __DIR__ . '/deinser-waf.php';

//Your boostrap start application code
```
# End of Selection
```


On each request, the script obtains the client’s IP, checks if it is in the local blocked IPs file (`.deinser-waf-ips`). If it is blocked, it sends a log to the API, returns a 403 response, and exits. If it is not blocked, it logs the request in the background (fire-and-forget) and lets the execution continue.

To update the IPs file, the WAF server can call your site with a POST request that includes `deinser_download_waf_ips=1` and `token=<token>`. The script detects this request and downloads the list of blocked IPs from `GET /api/blocked-ips?one-line=1`, saving it to `.deinser-waf-ips`. The `waf:autodownload-blocked-ips` command automates these calls for websites with auto-download configured.

## License

This repository and its code are Copyright © DEINSER.  
You are allowed to use and modify the code for your own projects as long as you do not sell it or charge for its use.  
Commercial redistribution or selling of this code is not permitted. All rights are reserved by DEINSER.
