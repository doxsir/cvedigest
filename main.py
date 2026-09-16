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

def usage():
    print("usage: cvedigest.py <ecosystem> [--min high] [--limit 10] [--digest weekly]")
    print("example: cvedigest.py pip --min high")
    print("  --digest weekly = вся неделя markdown-таблицей (экосистема опциональна)")
    sys.exit(0)

def md_digest(items, sev):
    # фильтр применяется и тут, чтобы --min работал в дайджесте
    if sev:
        items = [a for a in items if SEV.get(a.get("severity", "low").upper(), 0) >= SEV[sev]]
    print("| sev | score | cve | package | summary |")
    print("|---|---|---|---|---|")
    for a in items:
        cvss = a.get("cvss") or {}
        score = cvss.get("score")
        score_s = ("%.1f" % score) if isinstance(score, (int, float)) else ""
        pkgs = ", ".join(
            "%s/%s" % ((v.get("package") or {}).get("ecosystem", "?").lower(), (v.get("package") or {}).get("name", "?"))
            for v in (a.get("vulnerabilities") or [])[:2])
        link = a.get("html_url") or ("https://github.com/advisories/" + a["ghsa_id"])
        # markdown ломается от | в тексте, режем
        summary = a["summary"][:70].replace("|", "/")
        print("| %s | %s | [%s](%s) | %s | %s |" % (
            a.get("severity", "?").upper(), score_s,
            a.get("cve_id") or a["ghsa_id"], link, pkgs, summary))

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        usage()
    eco = None
    if args and not args[0].startswith("--"):
        eco = args[0]
        args = args[1:]
    sev = None
    limit = 10
    digest = False
    i = 0
    while i < len(args):
        if args[i] == "--min" and i + 1 < len(args):
            sev = args[i + 1].upper()
            i += 2
        elif args[i] == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
        elif args[i] == "--digest" and i + 1 < len(args) and args[i + 1] == "weekly":
            digest = True
            i += 2
        else:
            i += 1

    if sev and sev not in SEV:
        sys.exit("severity: low, moderate, high, critical")

    check_host()
    path = "/advisories?per_page=" + str(limit * 3)
    if digest:
        # неделя назад, формат YYYY-MM-DD (UTC, но кому важно)
        from datetime import date, timedelta
        week_ago = (date.today() - timedelta(days=7)).isoformat()
        path += "&published=%3E%3D" + week_ago
        if eco:
            path += "&ecosystem=" + eco
        if sev:
            # api хочет lowercase, иначе 422. полдня убил
            path += "&severity=" + sev.lower()
        items = fetch(path)
        md_digest(items, sev)
        return

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
        cvss = a.get("cvss") or {}
        score = cvss.get("score")
        score_s = ("%.1f" % score) if isinstance(score, (int, float)) else "n/a"
        print("[%s %s] %s" % (a.get("severity", "?").upper(), score_s, a["summary"][:80]))
        print("  %s  published %s" % (a.get("cve_id") or a["ghsa_id"], a.get("published_at", "?")[:10]))
        for v in (a.get("vulnerabilities") or [])[:3]:
            p = v.get("package", {})
            print("  - %s/%s %s" % (p.get("ecosystem", "?").lower(), p.get("name", "?"), v.get("vulnerable_version_range", "")))
        # ссылка на сам advisory всегда полезнее чем её отсутствие
        print("  -> " + a.get("html_url", "https://github.com/advisories/" + a["ghsa_id"]))
        print()

if __name__ == "__main__":
    main()
