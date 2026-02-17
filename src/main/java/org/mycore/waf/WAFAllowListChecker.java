package org.mycore.waf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mycore.common.MCRCache;
import org.mycore.common.config.MCRConfiguration2;
import org.mycore.frontend.MCRFrontendUtil;

/**
 * Handles allow list checks for IP addresses and paths.
 */
public class WAFAllowListChecker {

  private static final Logger LOGGER = LogManager.getLogger();

  private static final String CONFIG_ALLOWED_IPS = "MCR.WAF.AllowedIPs";
  private static final String CONFIG_ALLOWED_PATHS = "MCR.WAF.AllowedPaths";
  private static final String CONFIG_KNOWN_BOT_REVERSE_DNS = "MCR.WAF.KnownBotReverseDNS";
  private static final String CONFIG_KNOWN_BOT_USER_AGENTS = "MCR.WAF.KnownBotUserAgents";
  private static final String CONFIG_VERIFY_REVERSE_DNS = "MCR.WAF.VerifyReverseDNS";
  private static final String CONFIG_DNS_CACHE_CAPACITY = "MCR.WAF.DNSCacheCapacity";
  private static final String CONFIG_DNS_CACHE_TTL_MINUTES = "MCR.WAF.DNSCacheTTLMinutes";

  private static final int DEFAULT_DNS_CACHE_CAPACITY = 1000;
  private static final int DEFAULT_DNS_CACHE_TTL_MINUTES = 60;

  private final List<IPRange> allowedIPRanges;
  private final List<Pattern> allowedPathPatterns;
  private final List<Pattern> knownBotReverseDNSPatterns;
  private final List<String> knownBotUserAgents;
  private final boolean verifyReverseDNS;

  // Cache for reverse DNS lookups (IP -> Hostname), bounded with TTL via MCRCache
  private final MCRCache<String, String> reverseDNSCache;

  public WAFAllowListChecker() {
    this.allowedIPRanges = loadAllowedIPs();
    this.allowedPathPatterns = loadAllowedPaths();
    this.knownBotReverseDNSPatterns = loadKnownBotReverseDNS();
    this.knownBotUserAgents = loadKnownBotUserAgents();
    this.verifyReverseDNS = MCRConfiguration2.getBoolean(CONFIG_VERIFY_REVERSE_DNS).orElse(true);
    int capacity = MCRConfiguration2.getInt(CONFIG_DNS_CACHE_CAPACITY).orElse(DEFAULT_DNS_CACHE_CAPACITY);
    this.reverseDNSCache = new MCRCache<>(capacity, "WAF Reverse DNS");
  }

  private List<IPRange> loadAllowedIPs() {
    List<IPRange> ranges = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(CONFIG_ALLOWED_IPS);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] ips = config.get().split(",");
      for (String ip : ips) {
        ip = ip.trim();
        if (!ip.isEmpty()) {
          try {
            ranges.add(IPRange.parse(ip));
            LOGGER.info("Added IP range to allow list: {}", ip);
          } catch (IllegalArgumentException e) {
            LOGGER.error("Invalid IP range in configuration: {}", ip, e);
          }
        }
      }
    }

    return ranges;
  }

  private List<Pattern> loadAllowedPaths() {
    List<Pattern> patterns = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(CONFIG_ALLOWED_PATHS);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] paths = config.get().split(",");
      for (String path : paths) {
        path = path.trim();
        if (!path.isEmpty()) {
          try {
            patterns.add(Pattern.compile(path));
            LOGGER.info("Added path pattern to allow list: {}", path);
          } catch (Exception e) {
            LOGGER.error("Invalid path pattern in configuration: {}", path, e);
          }
        }
      }
    }

    return patterns;
  }

  private List<Pattern> loadKnownBotReverseDNS() {
    List<Pattern> patterns = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(CONFIG_KNOWN_BOT_REVERSE_DNS);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] hostPatterns = config.get().split(",");
      for (String hostPattern : hostPatterns) {
        hostPattern = hostPattern.trim();
        if (!hostPattern.isEmpty()) {
          try {
            // Convert wildcards to regex (e.g., *.googlebot.com -> .*\.googlebot\.com)
            String regex = hostPattern
                .replace(".", "\\.")
                .replace("*", ".*");
            patterns.add(Pattern.compile(regex));
            LOGGER.info("Added known bot reverse DNS pattern: {} (regex: {})", hostPattern, regex);
          } catch (Exception e) {
            LOGGER.error("Invalid known bot reverse DNS pattern in configuration: {}", hostPattern, e);
          }
        }
      }
    }

    return patterns;
  }

  private List<String> loadKnownBotUserAgents() {
    List<String> userAgents = new ArrayList<>();
    Optional<String> config = MCRConfiguration2.getString(CONFIG_KNOWN_BOT_USER_AGENTS);

    if (config.isPresent() && !config.get().isEmpty()) {
      String[] patterns = config.get().split(",");
      for (String pattern : patterns) {
        pattern = pattern.trim();
        if (!pattern.isEmpty()) {
          userAgents.add(pattern.toLowerCase(Locale.ROOT));
          LOGGER.info("Added known bot user agent pattern: {}", pattern);
        }
      }
    }

    return userAgents;
  }

  /**
   * Checks if the request IP is on the allow list.
   *
   * @param request the HTTP request
   * @return true if the IP is allowed, false otherwise
   */
  public boolean isIPAllowed(HttpServletRequest request) {
    if (allowedIPRanges.isEmpty()) {
      return false;
    }

    String remoteIP = MCRFrontendUtil.getRemoteAddr(request);
    for (IPRange range : allowedIPRanges) {
      if (range.contains(remoteIP)) {
        LOGGER.debug("IP {} is on allow list", remoteIP);
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if the request path is on the allow list.
   *
   * @param request the HTTP request
   * @return true if the path is allowed, false otherwise
   */
  public boolean isPathAllowed(HttpServletRequest request) {
    if (allowedPathPatterns.isEmpty()) {
      return false;
    }

    String basePath = URI.create(MCRFrontendUtil.getBaseURL(request)).getPath();
    if (basePath.endsWith("/")) {
      basePath = basePath.substring(0, basePath.length() - 1);
    }
    String requestURI = request.getRequestURI();
    if (!basePath.isEmpty() && requestURI.startsWith(basePath)) {
      requestURI = requestURI.substring(basePath.length());
    }
    for (Pattern pattern : allowedPathPatterns) {
      if (pattern.matcher(requestURI).matches()) {
        LOGGER.debug("Path {} matches allow list pattern: {}", requestURI, pattern);
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if the request comes from a known bot (based on User-Agent) whose reverse DNS
   * hostname matches the configured known bot DNS patterns.
   * The reverse DNS check is only performed if the User-Agent identifies the request
   * as coming from a known bot (e.g., Googlebot, bingbot, Baiduspider, Applebot).
   *
   * @param request the HTTP request
   * @return true if the User-Agent matches a known bot and the reverse DNS is verified, false otherwise
   */
  public boolean isKnownBotAllowedByReverseDNS(HttpServletRequest request) {
    if (knownBotReverseDNSPatterns.isEmpty() || knownBotUserAgents.isEmpty()) {
      return false;
    }

    // Only perform the expensive DNS check if the User-Agent identifies a known bot
    if (!isKnownBotUserAgent(request)) {
      return false;
    }

    String remoteIP = MCRFrontendUtil.getRemoteAddr(request);
    int ttlMinutes = MCRConfiguration2.getInt(CONFIG_DNS_CACHE_TTL_MINUTES).orElse(DEFAULT_DNS_CACHE_TTL_MINUTES);
    long ttlMs = (long) ttlMinutes * 60_000L;

    // Check cache: entry is valid if it was inserted within the TTL window
    String cachedHostname = reverseDNSCache.getIfUpToDate(remoteIP, System.currentTimeMillis() - ttlMs);
    if (cachedHostname != null) {
      return matchesKnownBotReverseDNSPattern(cachedHostname, remoteIP);
    }

    // Perform reverse DNS lookup
    String hostname = performReverseDNSLookup(remoteIP);
    if (hostname == null) {
      LOGGER.debug("No reverse DNS found for IP: {}", remoteIP);
      return false;
    }

    // Verify with forward DNS lookup if enabled
    if (verifyReverseDNS && !verifyForwardDNS(hostname, remoteIP)) {
      LOGGER.warn("Forward DNS verification failed for hostname: {} (IP: {})", hostname, remoteIP);
      return false;
    }

    // Cache the verified result
    reverseDNSCache.put(remoteIP, hostname);

    return matchesKnownBotReverseDNSPattern(hostname, remoteIP);
  }

  private boolean isKnownBotUserAgent(HttpServletRequest request) {
    String userAgent = request.getHeader("User-Agent");
    if (userAgent == null || userAgent.isEmpty()) {
      return false;
    }
    String userAgentLower = userAgent.toLowerCase(Locale.ROOT);
    for (String pattern : knownBotUserAgents) {
      if (userAgentLower.contains(pattern)) {
        LOGGER.debug("User-Agent '{}' matches known bot pattern '{}'", userAgent, pattern);
        return true;
      }
    }
    return false;
  }

  private String performReverseDNSLookup(String ip) {
    try {
      InetAddress addr = InetAddress.getByName(ip);
      String hostname = addr.getCanonicalHostName();

      // If getCanonicalHostName returns the IP address, DNS lookup failed
      if (hostname.equals(ip)) {
        return null;
      }

      LOGGER.debug("Reverse DNS lookup for {}: {}", ip, hostname);
      return hostname;

    } catch (UnknownHostException e) {
      LOGGER.debug("Reverse DNS lookup failed for IP: {}", ip, e);
      return null;
    }
  }

  private boolean verifyForwardDNS(String hostname, String originalIP) {
    try {
      InetAddress[] addresses = InetAddress.getAllByName(hostname);

      for (InetAddress addr : addresses) {
        if (addr.getHostAddress().equals(originalIP)) {
          LOGGER.debug("Forward DNS verification successful: {} -> {}", hostname, originalIP);
          return true;
        }
      }

      LOGGER.warn("Forward DNS verification failed: {} does not resolve to {}", hostname, originalIP);
      return false;

    } catch (UnknownHostException e) {
      LOGGER.warn("Forward DNS lookup failed for hostname: {}", hostname, e);
      return false;
    }
  }

  private boolean matchesKnownBotReverseDNSPattern(String hostname, String ip) {
    for (Pattern pattern : knownBotReverseDNSPatterns) {
      if (pattern.matcher(hostname).matches()) {
        LOGGER.debug("Reverse DNS {} (IP: {}) matches known bot DNS pattern: {}", hostname, ip, pattern);
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if either IP, path, or reverse DNS is on the allow list.
   *
   * @param request the HTTP request
   * @return true if IP, path, or reverse DNS is allowed, false otherwise
   */
  public boolean isAllowed(HttpServletRequest request) {
    return isIPAllowed(request) || isPathAllowed(request) || isKnownBotAllowedByReverseDNS(request);
  }
}
