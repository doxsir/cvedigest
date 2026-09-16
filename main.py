#!/usr/bin/env python3
# cvedigest - свежие уязвимости из GitHub Advisory DB прямо в терминал
# сделано за вечер, работает как работает
import sys, json, http.client, socket, ipaddress

API = "api.github.com"

# severity по возрастанию боли
SEV = {"LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}

def check_host():
    # паранойя: резолвим хост и отказываемся работать если он вдруг приватный
    for info in socket.getaddrinfo(API, 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            sys.exit("api host resolves to private address, not doing that")

def fetch(path):
    # коннект только к захардкоженному хосту, проверенному в check_host
    conn = http.client.HTTPSConnection(API, timeout=30)
    try:
        conn.request("GET", path, headers={"Accept": "application/vnd.github+json",
                                           "User-Agent": "cvedigest"})
        resp = conn.getresponse()
        if resp.status != 200:
            sys.exit("github api http " + str(resp.status))
        return json.loads(resp.read().decode("utf-8", "replace"))
    finally:
        conn.close()

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("usage: cvedigest.py <ecosystem> [--min high] [--limit 10]")
        print("example: cvedigest.py pip --min high")
        sys.exit(0)
    eco = args[0]
    sev = None
    limit = 10
    i = 1
    while i < len(args):
        if args[i] == "--min" and i + 1 < len(args):
            sev = args[i + 1].upper()
            i += 2
        elif args[i] == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
        else:
            i += 1

    if sev and sev not in SEV:
        sys.exit("severity: low, moderate, high, critical")

    check_host()
    path = "/advisories?per_page=" + str(limit * 3)
    if eco:
        path += "&ecosystem=" + eco  # экосистемы вроде pip/npm, квотить нечего
    if sev:
        # api хочет lowercase, иначе 422. полдня убил
        path += "&severity=" + sev.lower()

    items = fetch(path)  # берём с запасом, потом режем
    # фильтр "от этой тяжести и выше" т.к. api умеет только точное совпадение
    # (в ответе severity приходит в lowercase, потому .upper())
    if sev:
        items = [a for a in items if SEV.get(a.get("severity", "low").upper(), 0) >= SEV[sev]]
    items = items[:limit]

    if not items:
        print("nothing found, weird. try another ecosystem")
        return

    for a in items:
        print("[%s] %s" % (a.get("severity", "?").upper(), a["summary"][:90]))
        print("  %s  published %s" % (a.get("cve_id") or a["ghsa_id"], a.get("published_at", "?")[:10]))
        for v in (a.get("vulnerabilities") or [])[:3]:
            p = v.get("package", {})
            print("  - %s/%s %s" % (p.get("ecosystem", "?").lower(), p.get("name", "?"), v.get("vulnerable_version_range", "")))
        print()

if __name__ == "__main__":
    main()
