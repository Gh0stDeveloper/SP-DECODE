"""Offline VPS installer security checks; never access a real server."""
from __future__ import annotations
from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[4]
VPS=ROOT/"cloud/infra/vps"
class VPSInstallerTests(unittest.TestCase):
    def test_bash_parses(self):
        for name in ("install.sh","spdecodectl","android-build.sh"):
            with self.subTest(file=name):
                result=subprocess.run(["bash","-n",str(VPS/name)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
    def test_https_proxy_and_cidr(self):
        result=subprocess.run(["python3",str(VPS/"nginx-config.py"),"ghost.duckdns.org","198.51.100.12/32"],capture_output=True,text=True,check=True)
        for line in ("listen 443 ssl","allow 198.51.100.12/32","deny all","location ^~ /api/admin/","proxy_set_header X-Real-IP $remote_addr"):
            self.assertIn(line,result.stdout)
    def test_nginx_rejects_injection(self):
        for value in ("bad;inject","http://host.test","host.test/path","localhost","host.test\nserver {"):
            p=subprocess.run(["python3",str(VPS/"nginx-config.py"),value],capture_output=True)
            self.assertNotEqual(p.returncode,0,value)
    def test_admin_rejects_worldwide_allowlist(self):
        for cidr in ("0.0.0.0/0","::/0","198.51.100.0/24"):
            p=subprocess.run(["python3",str(VPS/"nginx-config.py"),
              "ghost.duckdns.org",cidr],capture_output=True)
            self.assertNotEqual(p.returncode,0,cidr)
    def test_installer_fail_closed(self):
        data=(VPS/"install.sh").read_text()
        for text in ("CLOUD_API_ENABLED=false","CLOUD_ADMIN_ENABLED=false","CLOUD_FORCE_MAINTENANCE=true","certbot certonly","nginx -t && systemctl reload nginx"):
            self.assertIn(text,data)
    def test_operator_updaters_and_rollback(self):
        data=(VPS/"spdecodectl").read_text()
        for word in ("api|web|panel","worker|engines","update app","rollback)","backup)","flock -x 9","git -C \"$REPO\" fetch","google-service-account","admin-password"):
            self.assertIn(word,data)
        self.assertNotIn("curl | bash",data)
    def test_android_signing_and_gate(self):
        data=(VPS/"android-build.sh").read_text()
        for word in ("--testing-only",":app:assembleRelease :app:bundleRelease","apksigner","jarsigner","cloud_c5_apk_audit.py","gradle-8.11.1","SPDECODE_CLOUD_RELEASE=true","sha256sum -c -"):
            self.assertIn(word,data)
        self.assertNotIn("curl | bash",data)
    def test_server_only_provider_secrets_forwarded(self):
        yml=(ROOT/"cloud/compose.yaml").read_text()
        for word in ("CLOUD_EHI_SIGN_KEY:","CLOUD_EHI_RESPONSE_KEY:","CLOUD_NUR_CATALOG_URL:","CLOUD_SITE_PUBLIC_ORIGIN:"):
            self.assertIn(word,yml)
        worker=yml.split("\n  decoder-worker:",1)[1]
        for word in ("CLOUD_EHI_SIGN_KEY:","CLOUD_ADMIN_SESSION_KEY:"):
            self.assertNotIn(word,worker)
if __name__=="__main__":unittest.main()
