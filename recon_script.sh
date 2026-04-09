#!/bin/bash
# =============================================================================
#  recon.sh — Bug Bounty Recon Toolkit
#  Usage: ./recon.sh <target-domain>
#  Example: ./recon.sh analvids.com
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
banner()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $1${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; }
ok()      { echo -e "  ${GREEN}[+]${RESET} $1"; }
info()    { echo -e "  ${CYAN}[*]${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${RESET} $1"; }
fail()    { echo -e "  ${RED}[-]${RESET} $1"; }
check_tool() { command -v "$1" &>/dev/null && ok "$1 found" || warn "$1 not installed — step may be skipped"; }

# ── Args ──────────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo -e "${RED}Usage: $0 <target-domain>${RESET}"
  echo -e "Example: $0 analvids.com"
  exit 1
fi

TARGET="${1,,}"          # lowercase
TARGET="${TARGET#https://}"  # strip protocol if accidentally included
TARGET="${TARGET#http://}"
TARGET="${TARGET%%/*}"   # strip trailing path
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="recon_${TARGET}_${TIMESTAMP}"

mkdir -p "$OUTDIR"/{dns,subdomains,http,ports,content,osint}

LOGFILE="$OUTDIR/recon.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ── Header ────────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}"
cat << 'EOF'
  ____  _____ ____ ___  _   _   ____  _   _
 |  _ \| ____/ ___/ _ \| \ | | / ___|| | | |
 | |_) |  _|| |  | | | |  \| | \___ \| |_| |
 |  _ <| |__| |__| |_| | |\  |  ___) |  _  |
 |_| \_\_____\____\___/|_| \_| |____/|_| |_|

 Bug Bounty Recon Toolkit
EOF
echo -e "${RESET}"
echo -e "  Target  : ${BOLD}${TARGET}${RESET}"
echo -e "  Output  : ${BOLD}${OUTDIR}/${RESET}"
echo -e "  Started : $(date)"
echo ""

# ── Dependency check ──────────────────────────────────────────────────────────
banner "Step 0 — Checking dependencies"
for tool in dig nslookup curl wget nmap whatweb ffuf subfinder amass; do
  check_tool "$tool"
done

# ── Step 1 — Passive DNS ──────────────────────────────────────────────────────
banner "Step 1 — Passive DNS & Certificate Transparency"

info "Querying crt.sh for subdomains..."
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for e in data:
        for n in e.get('name_value','').split('\n'):
            n = n.strip().lstrip('*.')
            if n: names.add(n)
    for n in sorted(names): print(n)
except: pass
" | tee "$OUTDIR/subdomains/crtsh.txt" \
  && ok "crt.sh done — $(wc -l < "$OUTDIR/subdomains/crtsh.txt") entries" \
  || fail "crt.sh query failed"

info "DNS record enumeration..."
DNS_OUT="$OUTDIR/dns/dns_records.txt"
{
  echo "=== A / AAAA ==="
  dig +noall +answer "$TARGET" A
  dig +noall +answer "$TARGET" AAAA

  echo -e "\n=== MX ==="
  dig +noall +answer "$TARGET" MX

  echo -e "\n=== TXT ==="
  dig +noall +answer "$TARGET" TXT

  echo -e "\n=== NS ==="
  dig +noall +answer "$TARGET" NS

  echo -e "\n=== SOA ==="
  dig +noall +answer "$TARGET" SOA

  echo -e "\n=== ANY (where permitted) ==="
  dig +noall +answer "$TARGET" ANY
} | tee "$DNS_OUT"
ok "DNS records saved → $DNS_OUT"

# ── Step 2 — Subdomain Discovery ──────────────────────────────────────────────
banner "Step 2 — Subdomain Discovery"

ALL_SUBS="$OUTDIR/subdomains/all_subdomains.txt"

# subfinder
if command -v subfinder &>/dev/null; then
  info "Running subfinder (passive)..."
  subfinder -d "$TARGET" -silent -o "$OUTDIR/subdomains/subfinder.txt" 2>/dev/null \
    && ok "subfinder done — $(wc -l < "$OUTDIR/subdomains/subfinder.txt") subdomains" \
    || fail "subfinder failed"
else
  warn "subfinder not found — skipping"
fi

# amass
if command -v amass &>/dev/null; then
  info "Running amass (passive, 60s timeout)..."
  timeout 60 amass enum -passive -d "$TARGET" \
    -o "$OUTDIR/subdomains/amass.txt" 2>/dev/null \
    && ok "amass done — $(wc -l < "$OUTDIR/subdomains/amass.txt") subdomains" \
    || warn "amass timed out or returned no results"
else
  warn "amass not found — skipping"
fi

# Merge all subdomains into one deduplicated list
info "Merging subdomain sources..."
cat "$OUTDIR/subdomains/"*.txt 2>/dev/null \
  | sort -u \
  | grep -E "\.?${TARGET//./\\.}$" \
  > "$ALL_SUBS" 2>/dev/null || true
ok "Total unique subdomains: $(wc -l < "$ALL_SUBS")"

# DNS-resolve discovered subdomains to confirm they're live
info "Resolving subdomains..."
LIVE_SUBS="$OUTDIR/subdomains/live_subdomains.txt"
> "$LIVE_SUBS"
while IFS= read -r sub; do
  if dig +short "$sub" A 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'; then
    echo "$sub" >> "$LIVE_SUBS"
  fi
done < "$ALL_SUBS"
ok "Live subdomains: $(wc -l < "$LIVE_SUBS")"

# ── Step 3 — HTTP Fingerprinting ──────────────────────────────────────────────
banner "Step 3 — HTTP Fingerprinting"

HTTP_OUT="$OUTDIR/http"

for host in "www.${TARGET}" "${TARGET}"; do
  for scheme in https http; do
    URL="${scheme}://${host}"
    info "Probing $URL ..."
    RESP_FILE="$HTTP_OUT/headers_${scheme}_${host//./_}.txt"
    if curl -sI --max-time 10 --location "$URL" \
      -H "User-Agent: Mozilla/5.0 (compatible; BugBountyRecon/1.0)" \
      -o /dev/null -D "$RESP_FILE" 2>/dev/null; then
      ok "Got response from $URL"
      cat "$RESP_FILE"
    else
      warn "No response from $URL"
    fi
    echo ""
  done
done

# whatweb
if command -v whatweb &>/dev/null; then
  info "Running whatweb..."
  whatweb --color=never -a 3 "https://www.${TARGET}" \
    | tee "$HTTP_OUT/whatweb.txt" 2>/dev/null \
    && ok "whatweb done" || fail "whatweb failed"
else
  warn "whatweb not found — skipping"
fi

# Interesting headers check
info "Checking security headers..."
HEADERS_FILE="$HTTP_OUT/security_headers.txt"
{
  echo "=== Security Header Audit: https://www.${TARGET} ==="
  HEADERS=$(curl -sI --max-time 10 "https://www.${TARGET}" 2>/dev/null)
  for h in "Strict-Transport-Security" "Content-Security-Policy" \
            "X-Frame-Options" "X-Content-Type-Options" \
            "Referrer-Policy" "Permissions-Policy" \
            "X-Powered-By" "Server" "X-Generator" \
            "X-AspNet-Version" "X-AspNetMvc-Version"; do
    val=$(echo "$HEADERS" | grep -i "^${h}:" | head -1)
    if [[ -n "$val" ]]; then
      echo "[PRESENT] $val"
    else
      echo "[MISSING] $h"
    fi
  done
} | tee "$HEADERS_FILE"
ok "Header audit saved → $HEADERS_FILE"

# ── Step 4 — Tech Stack ───────────────────────────────────────────────────────
banner "Step 4 — Technology Stack Detection"

TECH_OUT="$OUTDIR/http/tech_stack.txt"
info "Pulling page source clues..."
{
  echo "=== HTTP Response Headers ==="
  curl -sI --max-time 10 "https://www.${TARGET}" 2>/dev/null \
    | grep -iE "(server|x-powered|x-generator|cf-ray|x-drupal|x-wp|x-magento)"

  echo -e "\n=== Cookies ==="
  curl -sI --max-time 10 "https://www.${TARGET}" 2>/dev/null \
    | grep -i "set-cookie"

  echo -e "\n=== HTML meta / generator ==="
  curl -sL --max-time 15 "https://www.${TARGET}" 2>/dev/null \
    | grep -iE "(generator|framework|powered|version)" \
    | head -20
} | tee "$TECH_OUT"
ok "Tech stack hints saved → $TECH_OUT"

# ── Step 5 — Port Scan ────────────────────────────────────────────────────────
banner "Step 5 — Port Scan (nmap)"

NMAP_OUT="$OUTDIR/ports"
TARGET_IP=$(dig +short "$TARGET" A | head -1)

if [[ -z "$TARGET_IP" ]]; then
  warn "Could not resolve IP for $TARGET — skipping nmap"
else
  ok "Resolved $TARGET → $TARGET_IP"

  info "Running nmap top 1000 ports + service detection..."
  nmap -sV -sC \
    -T4 \
    --open \
    -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017 \
    -oN "$NMAP_OUT/nmap_targeted.txt" \
    -oX "$NMAP_OUT/nmap_targeted.xml" \
    "$TARGET_IP" 2>/dev/null \
    && ok "nmap done → $NMAP_OUT/nmap_targeted.txt" \
    || fail "nmap failed — try running as root for best results"
fi

# ── Step 6 — Web Content Discovery ───────────────────────────────────────────
banner "Step 6 — Web Content Discovery (ffuf)"

CONTENT_OUT="$OUTDIR/content"
WORDLIST=""
for wl in \
  "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt" \
  "/usr/share/seclists/Discovery/Web-Content/common.txt" \
  "/usr/share/wordlists/dirb/common.txt" \
  "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"; do
  if [[ -f "$wl" ]]; then WORDLIST="$wl"; break; fi
done

if command -v ffuf &>/dev/null && [[ -n "$WORDLIST" ]]; then
  info "Using wordlist: $WORDLIST"
  info "Running ffuf on https://www.${TARGET}/ ..."
  ffuf \
    -w "$WORDLIST" \
    -u "https://www.${TARGET}/FUZZ" \
    -mc 200,201,204,301,302,307,401,403,405 \
    -c -v \
    -t 40 \
    -timeout 10 \
    -o "$CONTENT_OUT/ffuf_results.json" \
    -of json \
    2>/dev/null \
    && ok "ffuf done → $CONTENT_OUT/ffuf_results.json" \
    || warn "ffuf returned no results or failed"

  # Also run on interesting subdomains
  if [[ -s "$LIVE_SUBS" ]]; then
    info "Running ffuf on live subdomains (top 5)..."
    head -5 "$LIVE_SUBS" | while IFS= read -r sub; do
      SAFE="${sub//./_}"
      ffuf -w "$WORDLIST" \
        -u "https://${sub}/FUZZ" \
        -mc 200,201,301,302,401,403 \
        -c -t 30 -timeout 10 \
        -o "$CONTENT_OUT/ffuf_${SAFE}.json" \
        -of json \
        2>/dev/null \
        && ok "ffuf done on $sub" || warn "ffuf failed on $sub"
    done
  fi
else
  [[ -z "$WORDLIST" ]] && warn "No wordlist found — install seclists: apt install seclists"
  ! command -v ffuf &>/dev/null && warn "ffuf not found — skipping content discovery"
fi

# ── Step 7 — OSINT Pointers ───────────────────────────────────────────────────
banner "Step 7 — OSINT Passive References"

OSINT_OUT="$OUTDIR/osint/osint_links.txt"
{
  echo "=== Shodan ==="
  echo "https://www.shodan.io/search?query=hostname%3A${TARGET}"
  echo ""
  echo "=== SecurityTrails (DNS history) ==="
  echo "https://securitytrails.com/domain/${TARGET}/dns"
  echo ""
  echo "=== VirusTotal (passive DNS) ==="
  echo "https://www.virustotal.com/gui/domain/${TARGET}"
  echo ""
  echo "=== crt.sh (cert transparency) ==="
  echo "https://crt.sh/?q=%.${TARGET}"
  echo ""
  echo "=== Google Dorks ==="
  echo "site:${TARGET}"
  echo "site:${TARGET} inurl:admin"
  echo "site:${TARGET} inurl:login"
  echo "site:${TARGET} filetype:pdf"
  echo "site:${TARGET} filetype:env OR filetype:config OR filetype:sql"
  echo "site:${TARGET} intitle:\"index of\""
  echo ""
  echo "=== Wayback Machine ==="
  echo "https://web.archive.org/web/*/${TARGET}"
  echo ""
  echo "=== URLScan ==="
  echo "https://urlscan.io/search/#domain:${TARGET}"
  echo ""
  echo "=== DNSDumpster ==="
  echo "https://dnsdumpster.com (search: ${TARGET})"
  echo ""
  echo "=== BGP / ASN lookup ==="
  echo "https://bgp.he.net/dns/${TARGET}"
} | tee "$OSINT_OUT"
ok "OSINT links saved → $OSINT_OUT"

# ── Wayback Machine quick pull ─────────────────────────────────────────────────
info "Pulling Wayback Machine URL list (last 1000 snapshots)..."
curl -s "http://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey&limit=1000" \
  | sort -u \
  | tee "$OUTDIR/osint/wayback_urls.txt" 2>/dev/null \
  && ok "Wayback URLs: $(wc -l < "$OUTDIR/osint/wayback_urls.txt") unique URLs" \
  || warn "Wayback query failed"

# ── Final Summary ─────────────────────────────────────────────────────────────
banner "Recon Complete"
echo -e "  Target       : ${BOLD}${TARGET}${RESET}"
echo -e "  Output dir   : ${BOLD}${OUTDIR}/${RESET}"
echo -e "  Log file     : ${BOLD}${LOGFILE}${RESET}"
echo ""
echo -e "  ${GREEN}Subdomains (total)  :${RESET} $(wc -l < "$ALL_SUBS" 2>/dev/null || echo 0)"
echo -e "  ${GREEN}Subdomains (live)   :${RESET} $(wc -l < "$LIVE_SUBS" 2>/dev/null || echo 0)"
echo -e "  ${GREEN}Wayback URLs        :${RESET} $(wc -l < "$OUTDIR/osint/wayback_urls.txt" 2>/dev/null || echo 0)"
echo ""
echo -e "  Finished: $(date)"
echo ""
echo -e "${CYAN}Next steps:${RESET}"
echo -e "  1. Review live subdomains: cat $LIVE_SUBS"
echo -e "  2. Check security headers: cat $OUTDIR/http/security_headers.txt"
echo -e "  3. Open OSINT links:       cat $OUTDIR/osint/osint_links.txt"
echo -e "  4. Grep Wayback for juicy paths:"
echo -e "     grep -iE '(admin|login|api|config|backup|\.env|\.sql)' $OUTDIR/osint/wayback_urls.txt"
echo ""
