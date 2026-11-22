import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "collector"))
os.environ["VULN_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
import collector as c

SAP_HTML = """<table><tr><td><a href="x">3778530</a></td><td>[CVE-2026-76964] Memory Corruption in SAP NetWeaver AS ABAP<br><b>Product</b> - SAP NetWeaver AS ABAP<br>Version(s) - KERNEL 7.53, 7.54</td><td>Critical</td><td>10.0</td></tr>
<tr><td>3804858</td><td>[CVE-2026-89119] CSRF in SAP Web Dispatcher<br>Additional CVE: CVE-2026-120014<br>Product - SAP Web Dispatcher<br>Version(s) - WEBDISP 7.93</td><td>Critical</td><td>9.6</td></tr></table>"""


class Tests(unittest.TestCase):
    def test_sap_parser(self):
        items = list(c.parse_sap(c.html_lines(SAP_HTML), "u", "2026-11-10"))
        self.assertEqual([i["id"] for i in items], ["CVE-2026-76964", "CVE-2026-89119"])
        self.assertEqual(items[0]["cvss"], 10.0)
        self.assertIn("KERNEL 7.53", items[0]["summary"])
        self.assertIn("CVE-2026-120014", items[1]["summary"])

    def test_recent(self):
        self.assertFalse(c.recent("2014-09-25"))
        self.assertTrue(c.recent(c.dt.date.today().isoformat()))

    def test_cpe_info(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "versionEndExcluding": "6.8"},
            {"vulnerable": False, "criteria": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}]}]}]}
        prods, vers = c.cpe_info(cve)
        self.assertEqual(prods, ["linux linux_kernel"])
        self.assertEqual(vers, ["linux_kernel < 6.8"])

    def test_severity(self):
        self.assertEqual([c.sev_of(x) for x in (9.8, 7.5, 5.0, 2.0, None)], ["Critical", "High", "Medium", "Low", "Medium"])

    def test_feed_escapes_xml(self):
        path = os.path.join(tempfile.mkdtemp(), "f.xml")
        c.write_feed([dict(id="CVE-1", title="a & b <x>", summary="s", url="javascript:alert(1)", kev=1,
                           severity="High", published="2026-11-01")], path)
        xml = open(path, encoding="utf-8").read()
        self.assertIn("a &amp; b &lt;x&gt;", xml)
        self.assertNotIn("javascript:", xml)

    def test_systems(self):
        osv = {"affected": [{"package": {"ecosystem": "Debian:12"}}, {"package": {"ecosystem": "Debian:11"}}, {"package": {"ecosystem": "Ubuntu:22.04:LTS"}},
                            {"package": {"ecosystem": "Red Hat:enterprise_linux:9::appstream"}}, {"package": {"ecosystem": "Go"}}, {"package": {"ecosystem": "Alpine:v3.19"}}, {"package": {"ecosystem": "SUSE:Linux Enterprise Server 15"}}]}
        self.assertEqual(c.osv_systems(osv), "Debian 12, 11; Ubuntu 22.04 LTS; Red Hat Enterprise Linux 9")
        cve = {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:o:alpinelinux:alpine_linux:3.19:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*"}]}]}]}
        self.assertEqual(c.cpe_systems(cve), ["Red Hat Enterprise Linux 8.0", "Debian 10.0"])

    def test_extra_system_and_upstream(self):
        c.CFG["extra_systems"] = ["TuxCare"]
        v = {"id": "CLSA-2025-1", "upstream": ["CVE-2024-9287"], "aliases": [],
             "affected": [{"package": {"ecosystem": "TuxCare:RHEL:7"}}, {"package": {"ecosystem": "TuxCare:Ubuntu:16.04"}}]}
        self.assertEqual(c.osv_cves(v), ["CVE-2024-9287"])
        self.assertEqual(c.osv_systems(v), "TuxCare RHEL 7; TuxCare Ubuntu 16.04")

    def test_osv_dump_handles_several_ecosystems(self):
        c.CFG["extra_systems"] = ["TuxCare"]
        c.CFG["osv_dumps"] = [{"eco": "Debian", "category": "Linux", "max": 5}, {"eco": "Ubuntu", "category": "Linux", "max": 5}]
        today = c.dt.date.today().isoformat()
        recs = {"DSA-1": {"id": "DSA-1", "aliases": ["CVE-2099-1", "CVE-2099-2"], "summary": "linux", "published": today + "T00:00:00Z",
                          "affected": [{"package": {"name": "linux", "ecosystem": "Debian:12"}}]},
                "USN-1": {"id": "USN-1", "aliases": ["CVE-2099-3"], "summary": "openssh", "published": today + "T00:00:00Z",
                          "affected": [{"package": {"name": "openssh", "ecosystem": "Ubuntu:22.04:LTS"}}]}}
        old = (c.text_of, c.http)
        c.text_of = lambda u: "2099-01-01T00:00:00Z,DSA-1" if "Debian" in u else "2099-01-01T00:00:00Z,USN-1"
        c.http = lambda u, data=None, timeout=30: recs[u.rsplit("/", 1)[-1][:-5].split("%2F")[-1]]
        try:
            out = [(i["id"], i["category"], i["systems"]) for i in c.from_osv_dump()]
        finally:
            c.text_of, c.http = old
        self.assertEqual(out, [("CVE-2099-1", "Kernel", "Debian 12"), ("CVE-2099-2", "Kernel", "Debian 12"), ("CVE-2099-3", "Linux", "Ubuntu 22.04 LTS")])

    def test_category(self):
        self.assertEqual(c.cat_of("SAP NetWeaver"), "SAP")
        self.assertEqual(c.cat_of("kubelet flaw"), "Kubernetes")
        self.assertEqual(c.cat_of("linux kernel nf_tables"), "Kernel")


if __name__ == "__main__":
    unittest.main()
