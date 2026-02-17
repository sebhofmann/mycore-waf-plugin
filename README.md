# MyCoRe WAF Plugin

A Web Application Firewall (WAF) plugin for [MyCoRe](https://www.mycore.de/) applications. It protects against bot attacks by issuing a **Proof of Work (PoW)** challenge that must be solved in the browser before any request is served. Legitimate search engine crawlers are let through via an allow list based on IP ranges, paths, or verified reverse DNS lookups.

## How it works

1. An incoming request hits the `WAFFilter`, which is automatically registered for all URLs (`/*`) on startup.
2. The filter checks allow lists in order: IP range → path → reverse DNS. Matching requests pass through immediately.
3. If no allow list matches, the filter checks for a valid `WAF-PASSED` cookie (a signed, IP-bound JWT).
4. If the cookie is missing or invalid, the client is redirected to the PoW challenge page.
5. The browser solves the SHA-256 PoW challenge in JavaScript and submits the solution.
6. The server validates the solution and, if correct, sets the `WAF-PASSED` cookie. The client is then redirected to the originally requested URL.
7. After too many failed attempts the client is shown a failure page.

```
Request
  │
  ├─ IP allow list match?         ──yes──> pass through
  ├─ Path allow list match?       ──yes──> pass through
  ├─ Reverse DNS allow list match?──yes──> pass through
  ├─ Valid WAF-PASSED cookie?     ──yes──> pass through
  ├─ Challenge solution submitted?──yes──> validate → set cookie → redirect to original URL
  ├─ Challenge page requested?    ──yes──> serve PoW challenge page
  └─ (anything else)              ──────> redirect to challenge page
```

## Installation

Add the JAR to your MyCoRe application. The plugin registers itself automatically via `MCR.Startup.Class` — no additional `web.xml` changes required.

```xml
<dependency>
    <groupId>org.mycore</groupId>
    <artifactId>mcr-waf-plugin</artifactId>
    <version>2022.06</version>
</dependency>
```

## Configuration

All settings are optional. The plugin works out of the box with sensible defaults.

### General

| Property          | Default | Description                         |
|-------------------|---------|-------------------------------------|
| `MCR.WAF.Enabled` | `true`  | Enable or disable the WAF entirely. |

### Allow Lists

Requests matching any allow list entry bypass the PoW challenge completely.

| Property                    | Default                                             | Description                                                                                                              |
|-----------------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `MCR.WAF.AllowedIPs`        | _(none)_                                            | Comma-separated list of IPs or CIDR ranges, e.g. `127.0.0.1,192.168.1.0/24`.                                             |
| `MCR.WAF.AllowedPaths`      | `/robots.txt,/sitemap.xml,/favicon.ico,/api/.*,...` | Comma-separated list of Java regex patterns matched against the request path (without context path).                     |
| `MCR.WAF.AllowedReverseDNS` | Google, Bing, Baidu, Apple crawlers                 | Comma-separated hostname patterns with `*` wildcards, e.g. `*.googlebot.com`. Verified by forward DNS lookup by default. |
| `MCR.WAF.VerifyReverseDNS`  | `true`                                              | When `true`, a successful reverse DNS match is additionally confirmed by a forward DNS lookup (prevents DNS spoofing).   |

#### Extending the default path allow list

Use MyCoRe's property inheritance to extend the defaults without losing them:

```properties
MCR.WAF.AllowedPaths=%MCR.WAF.AllowedPaths%,/my-public-api/.*
```

### Reverse DNS Cache

Reverse DNS lookups are expensive. Results are cached in a bounded `MCRCache`.

| Property                     | Default | Description                                                                   |
|------------------------------|---------|-------------------------------------------------------------------------------|
| `MCR.WAF.DNSCacheCapacity`   | `1000`  | Maximum number of IPs held in the cache (LRU eviction).                       |
| `MCR.WAF.DNSCacheTTLMinutes` | `60`    | How long a cached hostname is considered valid before the lookup is repeated. |

### Proof of Work Challenge

| Property                           | Default | Description                                                                                                                                                         |
|------------------------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `MCR.WAF.Difficulty`               | `16`    | Number of leading zero bits required in the SHA-256 hash. 16 bits ≈ 1–5 seconds on a modern browser. Increase for stricter protection, decrease for weaker clients. |
| `MCR.WAF.MaxAttempts`              | `3`     | Number of failed challenge attempts allowed before the failure page is shown.                                                                                       |
| `MCR.WAF.ChallengeExpiryMinutes`   | `2`     | How long a generated challenge token is valid.                                                                                                                      |
| `MCR.WAF.PassedTokenExpiryMinutes` | `1440`  | How long the `WAF-PASSED` cookie is valid (1 day). After expiry the client must solve the challenge again.                                                          |

### Custom Templates

The challenge and failure pages can be replaced with custom HTML/JS files on the classpath.

| Property                    | Default                   | Description                                                        |
|-----------------------------|---------------------------|--------------------------------------------------------------------|
| `MCR.WAF.ChallengeHtml`     | `pow-challenge.html`      | Classpath path to the challenge page template.                     |
| `MCR.WAF.ChallengeFailHtml` | `pow-challenge-fail.html` | Classpath path to the failure page template.                       |
| `MCR.WAF.ChallengeScript`   | `pow-challenge.js`        | Classpath path to the JavaScript embedded into the challenge page. |

Templates use `{{key}}` placeholders. Keys are resolved first from explicitly passed values (e.g. `pow_challenge_token`), then from the MyCoRe i18n system (`MCRTranslation`). The built-in templates support English and German.

## Security notes

- **WAF-PASSED cookie:** The cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` (when the application is served over HTTPS). It is a signed JWT bound to the client's IP address, so it cannot be reused from a different IP.
- **Challenge tokens:** Signed JWTs with a short expiry (default 2 minutes). They include the client IP, so a token captured by a third party cannot be used to pass the challenge.
- **Proof of Work:** The nonce submitted by the client is validated server-side using SHA-256. The difficulty is embedded in the signed token and cannot be tampered with by the client.
- **Reverse DNS spoofing:** When `MCR.WAF.VerifyReverseDNS=true` (the default), the plugin performs a forward DNS lookup to confirm that the resolved hostname actually points back to the original IP, preventing DNS spoofing attacks.
- **Bot detection:** In addition to the PoW check, the plugin inspects the browser fingerprint submitted with the solution (User-Agent, WebDriver flag, screen resolution, language list, etc.) to reject obvious bots even if they manage to solve the hash challenge.

## License

GNU General Public License v3 — see [LICENSE.txt](LICENSE.txt).
