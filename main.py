#!/usr/bin/env python3
# cvedigest - свежие уязвимости из GitHub Advisory DB прямо в терминал
# сделано за вечер, работает как работает
import sys, json, http.client, socket, ipaddress

API = "api.github.com"
KEV_HOST = "www.cisa.gov"
KEV_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# severity по возрастанию боли (в api всё lowercase)
SEV = {"low": 1, "moderate": 2, "high": 3, "critical": 4}

def check_host(host):
    # паранойя: резолвим хост и отказываемся работать если он вдруг приватный
    for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            sys.exit("host resolves to private address, not doing that")

def fetch(path, host=API):
    # коннект только к захардкоженным хостам, проверенным в check_host
    check_host(host)
    conn = http.client.HTTPSConnection(host, timeout=30)
    try:
        headers = {"User-Agent": "cvedigest"}
        if host == API:
            headers["Accept"] = "application/vnd.github+json"
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        if resp.status != 200:
            sys.exit("http " + str(resp.status) + " from " + host)
        return json.loads(resp.read().decode("utf-8", "replace"))
    finally:
        conn.close()

def fetch_kev():
    # список того что реально эксплуатируют в диком виде (cisa kev)
    data = fetch(KEV_PATH, KEV_HOST)
    return {v["cveID"] for v in data.get("vulnerabilities", [])}

def usage():
    print("usage: cvedigest.py <ecosystem> [--min high] [--limit 10] [--digest weekly] [--kev]")
    print("example: cvedigest.py pip --min high")
    print("  --digest weekly = вся неделя markdown-таблицей (экосистема опциональна)")
    print("  --kev = только то что в CISA Known Exploited, остальное в мусор")
    sys.exit(0)

def filter_items(items, sev, kev_set=None):
    # один фильтр на все режимы: --min это "не ниже", а не точное совпадение
    if sev:
        items = [a for a in items if SEV.get(a.get("severity", "low"), 0) >= SEV[sev.lower()]]
    if kev_set is not None:
        items = [a for a in items if a.get("cve_id") in kev_set]
    return items

def md_digest(items, sev, kev_set=None):
    items = filter_items(items, sev, kev_set)
    print("| sev | score | kev | cve | package | summary |")
    print("|---|---|---|---|---|---|")
    for a in items:
        cvss = a.get("cvss") or {}
        score = cvss.get("score")
        score_s = ("%.1f" % score) if isinstance(score, (int, float)) else ""
        in_kev = "yes" if kev_set and a.get("cve_id") in kev_set else ""
        pkgs = ", ".join(
            "%s/%s" % ((v.get("package") or {}).get("ecosystem", "?").lower(), (v.get("package") or {}).get("name", "?"))
            for v in (a.get("vulnerabilities") or [])[:2])
        link = a.get("html_url") or ("https://github.com/advisories/" + a["ghsa_id"])
        # markdown ломается от | в тексте, режем
        summary = a["summary"][:70].replace("|", "/")
        print("| %s | %s | %s | [%s](%s) | %s | %s |" % (
            a.get("severity", "?").upper(), score_s, in_kev,
            a.get("cve_id") or a["ghsa_id"], link, pkgs, summary))

def parse_args(args):
    # возвращает (eco, sev, limit, digest, kev); eco = None если первый аргумент флаг
    eco = None
    if args and not args[0].startswith("--"):
        eco = args[0]
        args = args[1:]
    sev = None
    limit = 10
    digest = False
    kev = False
    as_json = False
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
        elif args[i] == "--kev":
            kev = True
            i += 1
        elif args[i] == "--json":
            as_json = True
            i += 1
        else:
            # позиционная экосистема может стоять и после флагов
            if not args[i].startswith("--") and eco is None:
                eco = args[i]
            # неизвестный флаг молча пропускаем, зачем падать
            i += 1
    return eco, sev, limit, digest, kev, as_json

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        usage()
    eco, sev, limit, digest, kev, as_json = parse_args(args)
    if sev:
        sev = sev.lower()

    if sev and sev not in SEV:
        sys.exit("severity: low, moderate, high, critical")

    check_host(API)
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
            path += "&severity=" + sev
        items = fetch(path)
        # для дайджеста качаем все 30, лимит не режем — там таблица на неделю
        md_digest(items, sev, fetch_kev() if kev else None)
        return

    if eco:
        path += "&ecosystem=" + eco
    if sev:
        path += "&severity=" + sev

    items = fetch(path)  # берём с запасом, потом режем
    kev_set = fetch_kev() if kev else None
    items = filter_items(items, sev, kev_set)
    items = items[:limit]

    if not items:
        print("nothing found, weird. try another ecosystem")
        return

    if as_json:
        out = []
        for a in items:
            out.append({
                "cve": a.get("cve_id") or a["ghsa_id"],
                "ghsa": a["ghsa_id"],
                "severity": a.get("severity"),
                "cvss": (a.get("cvss") or {}).get("score"),
                "summary": a["summary"],
                "published": a.get("published_at", "?")[:10],
                "url": a.get("html_url"),
                "packages": [
                    {"ecosystem": (v.get("package") or {}).get("ecosystem"),
                     "name": (v.get("package") or {}).get("name"),
                     "range": v.get("vulnerable_version_range")}
                    for v in (a.get("vulnerabilities") or [])
                ],
            })
        print(json.dumps(out, indent=2))
        return

    for a in items:
        cvss = a.get("cvss") or {}
        score = cvss.get("score")
        score_s = ("%.1f" % score) if isinstance(score, (int, float)) else "n/a"
        in_kev = "[KEV]" if kev_set and a.get("cve_id") in kev_set else "     "
        print("%s [%s %s] %s" % (in_kev, a.get("severity", "?").upper(), score_s, a["summary"][:80]))
        print("  %s  published %s" % (a.get("cve_id") or a["ghsa_id"], a.get("published_at", "?")[:10]))
        for v in (a.get("vulnerabilities") or [])[:3]:
            p = v.get("package", {})
            print("  - %s/%s %s" % (p.get("ecosystem", "?").lower(), p.get("name", "?"), v.get("vulnerable_version_range", "")))
        # ссылка на сам advisory всегда полезнее чем её отсутствие
        print("  -> " + a.get("html_url", "https://github.com/advisories/" + a["ghsa_id"]))
        print()

if __name__ == "__main__":
    main()
