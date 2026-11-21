#!/usr/bin/env python3
"""Coletor para vulnerabilities-linux.com
Fontes: CISA KEV, feed oficial de CVEs do Kubernetes, OSV.dev, EPSS (FIRST).
Só biblioteca standard. Guarda em SQLite e exporta vulns.json para o portal.
Correr com cron/CronJob, por exemplo de hora a hora."""
import calendar, hashlib, sys, html as htmllib, json, os, re, sqlite3, time, urllib.parse, urllib.request
import datetime as dt
from email.utils import parsedate_to_datetime
try:  # parser XML seguro contra entity expansion; instalar: pip install defusedxml
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

CFG = json.load(open(os.path.join(os.path.dirname(__file__), "techlist.json")))
DB = os.environ.get("VULN_DB", "vulns.db")
OUT = os.environ.get("VULN_JSON", "vulns.json")
TEAMS = os.environ.get("TEAMS_WEBHOOK")  # opcional

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
K8S_URL = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
OSV_URL = "https://api.osv.dev/v1/query"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="


ERR = {}
LABEL = {"from_kev": "CISA KEV", "from_k8s": "Kubernetes CVE feed", "from_redhat": "Red Hat Security Data"}


def fail(label, e):
    ERR[label] = str(e)[:120]
    print(label, "falhou:", e)


def http(url, data=None, timeout=30):
    """Pedido com User-Agent; todo o conteudo externo e tratado como nao confiavel."""
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-portal-collector/1.0",
                                               "Content-Type": "application/json"})
    if "services.nvd.nist.gov" in url and os.environ.get("NVD_API_KEY"):
        req.add_header("apiKey", os.environ["NVD_API_KEY"])
    if data is not None:
        req.data = json.dumps(data).encode()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def clip(s, n):
    return (s or "").replace("\n", " ").strip()[:n]


def from_kev():
    kws = [k.lower() for k in CFG["kev_keywords"]]
    for v in http(KEV_URL).get("vulnerabilities", []):
        blob = f'{v.get("vendorProject","")} {v.get("product","")}'.lower()
        if any(k in blob for k in kws) or v.get("vendorProject", "").lower() == "sap":
            yield dict(id=v["cveID"], title=clip(v.get("vulnerabilityName"), 200),
                       product=clip(v.get("product"), 80),
                       category="SAP" if v.get("vendorProject", "").lower() == "sap" else "Linux",
                       summary=clip(v.get("shortDescription"), 560) + (" Known ransomware campaign use." if v.get("knownRansomwareCampaignUse") == "Known" else ""), severity="Alta",
                       cvss=None, kev=1, source="CISA KEV",
                       url=f'https://nvd.nist.gov/vuln/detail/{v["cveID"]}',
                       published=v.get("dateAdded", ""), mitigation=clip(v.get("requiredAction"), 400))


def from_k8s():
    for it in http(K8S_URL).get("items", []):
        cid = it.get("id", "")
        if not cid.startswith("CVE-"):
            continue
        yield dict(id=cid, title=clip(it.get("summary"), 200), product="kubernetes",
                   category="Kubernetes", summary=clip(it.get("content_text"), 600),
                   severity="Média", cvss=None, kev=0, source="Kubernetes CVE feed",
                   url=it.get("url", ""), published=(it.get("date_published") or "")[:10])


def from_osv():
    for t in CFG["osv"]:
        q = {"package": {"name": t["package"], "ecosystem": t["ecosystem"]}}
        try:
            res = http(OSV_URL, q).get("vulns", [])
        except Exception as e:
            fail("OSV", e); continue
        for v in res:
            cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            fixed = sorted({ev["fixed"] for a in v.get("affected", []) if a.get("package", {}).get("name") == t["package"]
                            for rg in a.get("ranges", []) for ev in rg.get("events", []) if "fixed" in ev})
            yield dict(mitigation=("Upgrade %s to a fixed version: %s" % (t["package"], ", ".join(fixed[:5]))) if fixed else None,
                       id=cves[0] if cves else v["id"], title=clip(v.get("summary") or v["id"], 200),
                       product=t["package"], category=t.get("category", "Linux"),
                       summary=clip(v.get("details"), 600), severity="Média", cvss=None, kev=0,
                       source=f'OSV ({t["ecosystem"]})', url=f'https://osv.dev/vulnerability/{v["id"]}',
                       published=(v.get("published") or "")[:10])


def cat_of(text):
    t = (text or "").lower()
    if re.search(r"\bsap\b", t): return "SAP"
    if re.search(r"kubernetes|kubelet|openshift|etcd|istio|cilium|calico|argo|rancher|k3s|kyverno|envoy|traefik|coredns", t): return "Kubernetes"
    if re.search(r"containerd|cri-o|podman|docker|runc|moby|buildah", t): return "Containers"
    if re.search(r"\bkernel\b", t): return "Kernel"
    return "Linux"


def from_osv_dump():
    """OSV por ecossistema (Linux kernel, Debian, Ubuntu, Alpine, Alma, Rocky, SUSE, Red Hat, Go filtrado):
    le <eco>/modified_id.csv (mais recentes primeiro) e vai buscar cada <eco>/<ID>.json em paralelo."""
    from concurrent.futures import ThreadPoolExecutor
    base = "https://osv-vulnerabilities.storage.googleapis.com/"
    cutoff = (dt.datetime.utcnow() - dt.timedelta(days=CFG.get("osv_days", 14))).strftime("%Y-%m-%dT%H:%M:%SZ")
    sevmap = {"critical": "Critical", "high": "High", "moderate": "Medium", "medium": "Medium", "low": "Low"}
    for e in CFG.get("osv_dumps", []):
        try:
            rows = text_of(base + urllib.parse.quote(e["eco"]) + "/modified_id.csv")
        except Exception as ex:
            fail("OSV", ex); continue
        ids = []
        for ln in rows.splitlines():
            ts, _, rid = ln.partition(",")
            if ts < cutoff: break
            ids.append(rid.strip() if "/" in rid else e["eco"] + "/" + rid.strip())
            if len(ids) >= e.get("max", 300): break

        def get(path):
            try:
                return http(base + urllib.parse.quote(path) + ".json")
            except Exception:
                return None
        with ThreadPoolExecutor(8) as ex:
            recs = list(ex.map(get, ids))
        for v in filter(None, recs):
            if v.get("withdrawn"): continue
            pk = next((a["package"]["name"] for a in v.get("affected", []) if a.get("package")), e["eco"])
            if e.get("match") and not re.search(e["match"], pk.lower()): continue
            cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            fixed = sorted({ev["fixed"] for a in v.get("affected", []) for rg in a.get("ranges", []) for ev in rg.get("events", []) if "fixed" in ev})
            sv = sevmap.get(str((v.get("database_specific") or {}).get("severity", "")).lower(), "Medium")
            yield dict(id=cves[0] if cves else v["id"], title=clip(v.get("summary") or v["id"], 200), product=clip(pk, 80),
                       category="Kernel" if e["eco"] == "Linux" else (cat_of(pk) if e.get("match") else e["category"]),
                       summary=clip(v.get("details"), 600), severity=sv, cvss=None, kev=0, source=f"OSV ({e['eco']})",
                       url=f'https://osv.dev/vulnerability/{v["id"]}', published=(v.get("published") or "")[:10],
                       mitigation=("Upgrade %s to a fixed version: %s" % (pk, ", ".join(fixed[:5]))) if fixed else None)


def sev_of(score):
    if score is None: return "Medium"
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


def nvd_item(it, kw):
    c = it["cve"]; m = c.get("metrics", {}); score = None
    for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
        if m.get(k):
            score = m[k][0]["cvssData"]["baseScore"]; break
    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    return dict(id=c["id"], title=clip(desc, 200), product=kw["q"], category=kw["category"], summary=clip(desc, 600),
                severity=sev_of(score), cvss=score, kev=0, source="NVD",
                url=f'https://nvd.nist.gov/vuln/detail/{c["id"]}', published=c.get("published", "")[:10])


def from_nvd():
    """NVD API 2.0 paginado: CVEs modificados nos ultimos N dias (max 120) por palavra-chave. Com NVD_API_KEY e ~10x mais rapido."""
    days = min(int(os.environ.get("NVD_DAYS", CFG.get("nvd_days", 30))), 120)
    end = dt.datetime.utcnow(); start = end - dt.timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"; pause = 0.7 if os.environ.get("NVD_API_KEY") else 6
    for kw in CFG.get("nvd_keywords", []):
        idx, cap = 0, kw.get("max", 300)
        while idx < cap:
            url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200&startIndex=%d&keywordSearch=" % idx
                   + urllib.parse.quote(kw["q"]) + "&lastModStartDate=" + start.strftime(fmt) + "&lastModEndDate=" + end.strftime(fmt))
            try:
                res = http(url)
            except Exception as e:
                fail("NVD", e); break
            time.sleep(pause)
            items = res.get("vulnerabilities", [])
            for it in items:
                yield nvd_item(it, kw)
            idx += len(items)
            if not items or idx >= res.get("totalResults", 0):
                break


def from_ghsa():
    """GitHub Security Advisories (revistos) por ecossistema, filtrados pelas palavras da lista."""
    kws = [k.lower() for k in CFG["kev_keywords"]]
    for eco in CFG.get("ghsa_ecosystems", []):
        try:
            res = http(f"https://api.github.com/advisories?type=reviewed&per_page=100&ecosystem={eco}")
        except Exception as e:
            fail("GitHub Advisories", e); continue
        for a in res:
            pk = " ".join(v["package"]["name"] for v in a.get("vulnerabilities", []) if v.get("package"))
            if not any(k in (a.get("summary", "") + " " + pk).lower() for k in kws):
                continue
            sc = (a.get("cvss") or {}).get("score")
            pv = sorted({f'{v["package"]["name"]} {v["first_patched_version"]}' for v in a.get("vulnerabilities", []) if v.get("package") and isinstance(v.get("first_patched_version"), str)})
            yield dict(id=a.get("cve_id") or a["ghsa_id"], title=clip(a.get("summary"), 200), product=clip(pk, 80),
                       category="Containers", summary=clip(a.get("description"), 600),
                       severity=(a.get("severity") or "medium").capitalize(), cvss=sc, kev=0,
                       source="GitHub Advisories", url=a["html_url"], published=(a.get("published_at") or "")[:10],
                       mitigation=("Upgrade to: " + ", ".join(pv)) if pv else None)


def text_of(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-portal-collector/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read(8_000_000).decode("utf-8", "replace")


def html_lines(raw):
    raw = re.sub(r"(?is)<(script|style)\b.*?</\1>", "", raw)
    raw = re.sub(r"(?i)</?(?:a|b|i|u|em|strong|span|font)\b[^>]*>", "", raw)
    raw = re.sub(r"<[^>]+>", "\n", raw)
    return [l.strip() for l in htmllib.unescape(raw).splitlines() if l.strip()]


def patch_day(y, m):
    tues = [d for d in calendar.Calendar().itermonthdates(y, m) if d.month == m and d.weekday() == 1]
    return tues[1].isoformat()


def parse_sap(lines, url, day):
    """Tabela do SAP Security Patch Day: nota, titulo [CVE], Product/Library, Version(s), prioridade, CVSS."""
    recs, rec = [], None
    for ln in lines:
        mo = re.match(r"^(\d{7}|GHSA-[0-9a-z-]+)\b", ln)
        if mo and len(ln) < 40:
            rec = {"note": mo.group(1), "lines": []}; recs.append(rec); continue
        if rec is not None:
            rec["lines"].append(ln)
    for r in recs:
        title = prio = prod = ver = cvss = None; extra = []
        for ln in r["lines"]:
            if ln.startswith(("Update to Security Note", "(opens in new tab)")): continue
            if re.match(r"^(Additional CVEs?|CVEs):", ln): extra += re.findall(r"CVE-\d+-\d+", ln); continue
            if re.match(r"^(Product|Library)\b", ln): prod = re.sub(r"^(Product|Library)\s*[-\u2013]?\s*", "", ln); continue
            if ln.startswith("Version"): ver = re.sub(r"^Version\(s\)\s*[-\u2013]?\s*", "", ln); continue
            if prio is None and ln in ("Critical", "High", "Medium", "Low"): prio = ln; continue
            if prio and cvss is None and re.fullmatch(r"\d+(\.\d+)?", ln): cvss = float(ln); continue
            if title is None: title = ln
        if not (title and prio): continue
        cves = re.findall(r"CVE-\d+-\d+", title) + extra
        yield dict(id=cves[0] if cves else "SAP-NOTE-" + r["note"],
                   title=clip(re.sub(r"^\[[^\]]*\]\s*", "", title), 200), product=clip(prod, 80), category="SAP",
                   summary=clip(f"SAP Security Note {r['note']}. Product: {prod}. Affected versions: {ver}."
                                + (f" Additional CVEs: {', '.join(cves[1:])}." if len(cves) > 1 else ""), 900),
                   severity=prio, cvss=cvss, kev=0, source="SAP Security Patch Day", url=url, published=day,
                   mitigation=f"Apply the fix from SAP Security Note {r['note']} to all affected versions.")


def from_sap():
    today = dt.date.today()
    for k in range(CFG.get("sap_months", 6)):
        y, m = today.year, today.month - k
        while m < 1:
            m += 12; y -= 1
        url = ("https://support.sap.com/en/my-support/knowledge-base/security-notes-news/"
               f"{calendar.month_name[m].lower()}-{y}.html")
        try:
            lines = html_lines(text_of(url))
        except Exception as e:
            fail("SAP Security Patch Day", e); continue
        yield from parse_sap(lines, url, patch_day(y, m))


def from_redhat():
    kws = [k.lower() for k in CFG["kev_keywords"]]
    after = (dt.date.today() - dt.timedelta(days=CFG.get("redhat_days", 60))).isoformat()
    sev = {"critical": "Critical", "important": "High", "moderate": "Medium", "low": "Low"}
    for v in http(f"https://access.redhat.com/hydra/rest/securitydata/cve.json?after={after}&per_page=1000"):
        blob = (v.get("bugzilla_description", "") + " " + " ".join(v.get("affected_packages", []) or [])).lower()
        yield dict(id=v["CVE"], title=clip(v.get("bugzilla_description"), 200), product=clip(" ".join(v.get("affected_packages", []) or [])[:80], 80),
                   category=cat_of(blob), summary=clip(v.get("bugzilla_description"), 600),
                   severity=sev.get((v.get("severity") or "").lower(), "Medium"), cvss=v.get("cvss3_score"), kev=0,
                   source="Red Hat Security Data", url=v.get("resource_url", ""), published=(v.get("public_date") or "")[:10])


def to_date(s):
    try:
        return parsedate_to_datetime(s).date().isoformat()
    except Exception:
        return (s or "")[:10]


def from_rss():
    kws = [k.lower() for k in CFG["kev_keywords"]]
    for f in CFG.get("rss", []):
        try:
            root = ET.fromstring(text_of(f["url"]).encode("utf-8"))
        except Exception as e:
            fail(f["name"], e); continue
        n = 0
        for el in root.iter():
            if el.tag.rsplit("}", 1)[-1] not in ("item", "entry"):
                continue
            ch = {c.tag.rsplit("}", 1)[-1]: c for c in el}
            title = (ch["title"].text or "") if "title" in ch else ""
            link = (ch["link"].text or ch["link"].get("href", "")) if "link" in ch else ""
            body = next((ch[k].text or "" for k in ("description", "summary", "content") if k in ch), "")
            when = next((ch[k].text or "" for k in ("pubDate", "updated", "date", "published") if k in ch), "")
            text = (title + " " + body).lower()
            if f.get("filter", True) and not any(k in text for k in kws):
                continue
            cves = re.findall(r"CVE-\d+-\d+", title + " " + body)
            tid = re.match(r"^[A-Z]{2,4}-[\d-]+", title)
            cat = "SAP" if re.search(r"\bsap\b", text) else f["category"]
            yield dict(id=cves[0] if cves else tid.group(0) if tid else "RSS-" + hashlib.sha1(title.encode()).hexdigest()[:10],
                       title=clip(title, 200), product=f["name"], category=cat,
                       summary=clip(re.sub(r"<[^>]+>", " ", htmllib.unescape(body)), 600), severity="Medium", cvss=None, kev=0,
                       source=f["name"], url=link, published=to_date(when))
            n += 1
            if n >= f.get("limit", 50):
                break


def from_euvd():
    """ENISA EU Vulnerability Database: exploradas e criticas recentes, filtradas por palavras da lista."""
    kws = [k.lower() for k in CFG["kev_keywords"]]
    for ep, kev in (("exploitedvulnerabilities", 1), ("criticalvulnerabilities", 0)):
        try:
            data = http("https://euvdservices.enisa.europa.eu/api/" + ep)
        except Exception as e:
            fail("ENISA EUVD", e); continue
        for v in (data if isinstance(data, list) else data.get("items", [])):
            blob = json.dumps(v)
            if not any(k in blob.lower() for k in kws):
                continue
            cves = re.findall(r"CVE-\d+-\d+", blob)
            vid = cves[0] if cves else v.get("id", "EUVD")
            score = v.get("baseScore")
            score = float(score) if isinstance(score, (int, float, str)) and str(score).replace(".", "", 1).isdigit() else None
            yield dict(id=vid, title=clip(v.get("description"), 200), product="EUVD", category="SAP" if "sap" in blob.lower().split() else "Linux",
                       summary=clip(v.get("description"), 600), severity=sev_of(score) if score else "High", cvss=score, kev=kev,
                       source="ENISA EUVD", url="https://euvd.enisa.europa.eu/vulnerability/" + vid,
                       published=(v.get("datePublished") or "")[:10])


def epss(ids):
    out = {}
    ids = list(ids)
    for i in range(0, len(ids), 50):
        chunk = [x for x in ids[i:i + 50] if x.startswith("CVE-")]
        if not chunk:
            continue
        try:
            for r in http(EPSS_URL + ",".join(chunk)).get("data", []):
                out[r["cve"]] = float(r["epss"])
        except Exception as e:
            print("EPSS falhou", e)
    return out


def write_feed(rows, path):
    """RSS 2.0 com as KEV e criticas mais recentes."""
    from xml.sax.saxutils import escape as x
    site = os.environ.get("SITE_URL", "https://vulnerabilities-linux.com/")
    out = ['<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Linux, Cloud-Native &amp; SAP Vulnerability Intelligence</title>'
           f"<link>{x(site)}</link><description>Exploited and critical vulnerabilities</description>"]
    for r in [r for r in rows if r["kev"] or r["severity"] == "Critical"][:50]:
        try:
            pd = dt.datetime.strptime(r["published"], "%Y-%m-%d").strftime("%a, %d %b %Y 00:00:00 +0000")
        except Exception:
            pd = ""
        link = r["url"] if (r["url"] or "").startswith(("http://", "https://")) else site
        out.append(f"<item><title>{x(r['id'] + ': ' + (r['title'] or ''))}</title><link>{x(link)}</link>"
                   f"<guid isPermaLink=\"false\">{x(r['id'])}</guid><description>{x(r['summary'] or '')}</description>"
                   + (f"<pubDate>{pd}</pubDate>" if pd else "") + "</item>")
    open(path, "w", encoding="utf-8").write("".join(out) + "</channel></rss>")


def main():
    db = sqlite3.connect(DB)
    db.execute("""CREATE TABLE IF NOT EXISTS vulns(id TEXT, source TEXT, title TEXT, product TEXT,
      category TEXT, summary TEXT, severity TEXT, cvss REAL, kev INT, epss REAL, url TEXT,
      published TEXT, first_seen TEXT, mitigation TEXT, PRIMARY KEY(id, source))""")
    try:
        db.execute("ALTER TABLE vulns ADD COLUMN mitigation TEXT")  # migracao de bases antigas
    except sqlite3.OperationalError:
        pass
    now = dt.datetime.utcnow().isoformat(timespec="seconds")
    new_kev = []
    for fn in (from_kev, from_k8s, from_osv, from_osv_dump, from_nvd, from_ghsa, from_sap, from_redhat, from_rss, from_euvd):
        try:
            items = list(fn())
        except Exception as e:
            fail(LABEL.get(fn.__name__, fn.__name__), e); continue
        for v in items:
            exists = db.execute("SELECT 1 FROM vulns WHERE id=? AND source=?", (v["id"], v["source"])).fetchone()
            if not exists:
                db.execute("INSERT INTO vulns(id,source,title,product,category,summary,severity,cvss,kev,epss,url,published,first_seen,mitigation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (v["id"], v["source"], v["title"], v["product"], v["category"], v["summary"],
                            v["severity"], v["cvss"], v["kev"], None, v["url"], v["published"], now, v.get("mitigation")))
                if v["kev"]:
                    new_kev.append(v)
    db.commit()
    scores = epss(r[0] for r in db.execute("SELECT DISTINCT id FROM vulns"))
    for cid, s in scores.items():
        db.execute("UPDATE vulns SET epss=? WHERE id=?", (s, cid))
    db.commit()
    rows = db.execute("""SELECT id,source,title,product,category,summary,severity,cvss,kev,epss,url,published,mitigation
        FROM vulns ORDER BY kev DESC, COALESCE(epss,0) DESC, published DESC LIMIT 8000""").fetchall()
    keys = ["id", "source", "title", "product", "category", "summary", "severity", "cvss", "kev", "epss", "url", "published", "mitigation"]
    json.dump([dict(zip(keys, r)) for r in rows], open(OUT, "w"), ensure_ascii=False)
    outdir = os.path.dirname(OUT) or "."
    json.dump({"generated_at": now, "total": len(rows), "errors": ERR}, open(os.path.join(outdir, "status.json"), "w"))
    write_feed([dict(zip(keys, r)) for r in rows], os.path.join(outdir, "feed.xml"))
    print(f"{len(rows)} registos exportados; {len(new_kev)} novos KEV")
    if not rows:
        sys.exit(1)  # nenhuma fonte respondeu: o workflow falha de forma visivel
    if TEAMS and new_kev:
        text = "Novas vulnerabilidades exploradas (CISA KEV):\n" + "\n".join(f'- {v["id"]}: {v["title"]}' for v in new_kev[:10])
        urllib.request.urlopen(urllib.request.Request(TEAMS, json.dumps({"text": text}).encode(),
                               {"Content-Type": "application/json"}), timeout=15)


if __name__ == "__main__":
    main()
