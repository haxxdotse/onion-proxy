"""One-click Windows launcher and local dashboard for onion-proxy."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
import winreg
import winsound
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from database.storage import initialize, save_event
from inspection.http import inspect_request
from network.analyzer import analyze_request_details
from security.blocklist import BlockRule, find_block_rule, load_blocklist
from security.domain_filter import is_ignored_domain, load_ignored_domains
from security.policy import decide
from ui.console import blocked_response_body


APP_DATA = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "onion-proxy"
LEGACY_APP_DATA_DIRS = (
    Path(os.environ.get("LOCALAPPDATA", Path.home())) / "FegisProxy",  # migrate the previous release's settings
    Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AegisSecurity",
    Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SecurityBox",
)
MITMPROXY_DIR = APP_DATA / "mitmproxy"
PROXY_HOST = "127.0.0.1"
PREFERRED_PORT = 8080
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37
_INSTANCE_MUTEX = None


def prepare_app_data() -> tuple[Path, Path]:
    APP_DATA.mkdir(parents=True, exist_ok=True)
    for legacy_dir in LEGACY_APP_DATA_DIRS:
        if not legacy_dir.is_dir():
            continue
        for old_item in legacy_dir.iterdir():
            new_item = APP_DATA / old_item.name
            if not new_item.exists():
                shutil.move(str(old_item), str(new_item))
        try:
            legacy_dir.rmdir()
        except OSError:
            pass
    MITMPROXY_DIR.mkdir(parents=True, exist_ok=True)
    ignore_path = APP_DATA / "ignore_domains.txt"
    if not ignore_path.exists():
        bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
        source = bundle_dir / "settings" / "ignore_domains.txt"
        if not source.is_file():
            source = bundle_dir / "ignore_domains.txt"
        if source.is_file():
            shutil.copyfile(source, ignore_path)
        else:
            ignore_path.write_text("# One domain per line; subdomains are included.\n", encoding="utf-8")
    blocklist_path = APP_DATA / "blocklist.txt"
    if not blocklist_path.exists():
        bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
        bundled_blocklist = bundle_dir / "settings" / "blocklist.txt"
        if not bundled_blocklist.is_file():
            bundled_blocklist = bundle_dir / "blocklist.txt"
        if bundled_blocklist.is_file():
            shutil.copyfile(bundled_blocklist, blocklist_path)
        else:
            blocklist_path.write_text(
                "# One domain or URL per line; see examples in this file.\n", encoding="utf-8"
            )
    initialize()
    return ignore_path, blocklist_path


def load_preferences() -> dict:
    path = APP_DATA / "preferences.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_preferences(value: dict) -> None:
    APP_DATA.mkdir(parents=True, exist_ok=True)
    path = APP_DATA / "preferences.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def find_available_port() -> int:
    for port in range(PREFERRED_PORT, PREFERRED_PORT + 20):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((PROXY_HOST, port))
        except OSError:
            continue
        else:
            return port
        finally:
            probe.close()
    raise OSError("Не удалось найти свободный порт прокси (8080–8099).")


class WindowsProxySettings:
    """Temporarily route this Windows user's system proxy through onion-proxy."""

    VALUE_NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")

    def __init__(self, port: int) -> None:
        self.port = port
        self.original: dict[str, tuple[object, int] | None] = {}
        self.active = False

    def enable(self) -> None:
        access = winreg.KEY_READ | winreg.KEY_WRITE
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, access) as key:
            for name in self.VALUE_NAMES:
                try:
                    self.original[name] = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    self.original[name] = None
            self.active = True
            try:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{PROXY_HOST}:{self.port}")
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass
            except Exception:
                self.restore()
                raise
        self._notify_windows()

    def restore(self) -> None:
        if not self.active:
            return
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
            for name, value in self.original.items():
                if value is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
                else:
                    data, value_type = value
                    winreg.SetValueEx(key, name, 0, value_type, data)
        self.active = False
        self._notify_windows()

    @staticmethod
    def _notify_windows() -> None:
        wininet = ctypes.WinDLL("wininet", use_last_error=True)
        wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


class UserCertificate:
    """Trust mitmproxy's generated CA for the current user only while active."""

    def __init__(self) -> None:
        self.serial: str | None = None
        self.added = False

    def install(self) -> None:
        certificate_path = MITMPROXY_DIR / "mitmproxy-ca-cert.pem"
        if not certificate_path.is_file():
            raise FileNotFoundError(f"Не создан локальный HTTPS-сертификат: {certificate_path}")
        from cryptography import x509

        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        self.serial = format(certificate.serial_number, "X")
        certutil = shutil.which("certutil.exe") or shutil.which("certutil")
        if not certutil:
            raise RuntimeError("Не найдена встроенная утилита Windows certutil.exe")
        result = subprocess.run(
            [certutil, "-user", "-addstore", "Root", str(certificate_path)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            details = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"Не удалось установить локальный HTTPS-сертификат. {details}")
        self.added = True

    def remove(self) -> None:
        if not self.added or not self.serial:
            return
        certutil = shutil.which("certutil.exe") or shutil.which("certutil")
        if certutil:
            subprocess.run(
                [certutil, "-user", "-delstore", "Root", self.serial],
                capture_output=True, text=True, check=False,
            )
        self.added = False


@dataclass
class PendingAlert:
    application: str
    domain: str
    url: str
    findings: list[str]
    evidence: list[dict[str, str]]
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future[str]


class OnionProxyAddon:
    def __init__(self, certificate: UserCertificate, proxy: WindowsProxySettings,
                 ignored_domains: frozenset[str], block_rules: tuple[BlockRule, ...],
                 events: queue.Queue) -> None:
        self.certificate = certificate
        self.proxy = proxy
        self.ignored_domains = ignored_domains
        self.block_rules = block_rules
        self.events = events
        self.sound_enabled = True
        self.observation_mode = False
        self.last_alert_sound: dict[str, float] = {}
        self.last_block_db: dict[str, float] = {}
        self.block_counters: dict[str, list[float | int]] = {}

    def running(self) -> None:
        try:
            self.certificate.install()
            self.proxy.enable()
        except Exception:
            self.cleanup()
            raise
        self.events.put(("status", "running", self.proxy.port))

    async def request(self, flow: http.HTTPFlow) -> None:
        request_data = inspect_request(flow.request)
        domain = request_data["host"]
        rule = find_block_rule(request_data["url"], domain, self.block_rules)
        if rule is not None:
            flow.response = http.Response.make(
                403,
                f"Blocked by onion-proxy blocklist.\nDestination: {request_data['url']}\nRule: {rule.original}\n".encode("utf-8"),
                {"Content-Type": "text/plain; charset=utf-8"},
            )
            self._record_blocklist_block(domain, request_data["url"], rule)
            return
        if is_ignored_domain(domain, self.ignored_domains):
            return
        if not request_data["is_upload"]:
            return
        if request_data.get("body_unavailable"):
            findings = ["UNSCANNED_UPLOAD"]
            evidence = [{"type": "UPLOAD", "value": "Request body unavailable or could not be decoded; contents were not inspected",
                         "source": "fail-safe upload warning"}]
        elif request_data["size"] > request_data["max_body_size"]:
            findings = ["UNSCANNED_UPLOAD"]
            evidence = [{
                "type": "UPLOAD",
                "value": f"{request_data['size']} bytes; exceeds the inspection limit; contents were not inspected",
                "source": "fail-safe upload warning",
            }]
        else:
            findings, evidence = analyze_request_details(flow.request)
        if not findings:
            return
        application = "UNKNOWN"
        action = "MONITOR" if self.observation_mode else decide(application, domain, findings)
        if action == "ASK":
            now = time.monotonic()
            if self.sound_enabled and now - self.last_alert_sound.get(domain, 0.0) >= 2.0:
                winsound.MessageBeep(winsound.MB_ICONHAND)
                self.last_alert_sound[domain] = now
            loop = asyncio.get_running_loop()
            future: asyncio.Future[str] = loop.create_future()
            self.events.put(("alert", PendingAlert(application, domain, request_data["url"], findings, evidence, loop, future)))
            action = await future
        if action == "BLOCK":
            flow.response = http.Response.make(
                403, blocked_response_body(domain, findings), {"Content-Type": "text/plain"},
            )
        save_event(application, domain, findings, action)
        self.events.put(("event", datetime.now().strftime("%H:%M:%S"), action, domain, findings, evidence))

    def _record_blocklist_block(self, domain: str, url: str, rule: BlockRule) -> None:
        now = time.monotonic()
        # Keep the dashboard useful during noisy polling: aggregate repeats per domain.
        state = self.block_counters.setdefault(domain, [now, 0])
        state[1] = int(state[1]) + 1
        if now - float(state[0]) >= 1.0 or int(state[1]) == 1:
            count = int(state[1])
            state[0], state[1] = now, 0
            self.events.put(("blocklist", datetime.now().strftime("%H:%M:%S"), domain, url, rule.original, count))
        if now - self.last_block_db.get(domain, 0.0) >= 60.0:
            save_event("UNKNOWN", domain, ["BLOCKLIST"], "BLOCK")
            self.last_block_db[domain] = now

    def done(self) -> None:
        self.cleanup()
        self.events.put(("status", "stopped", None))

    def cleanup(self) -> None:
        try:
            self.proxy.restore()
        finally:
            self.certificate.remove()


async def run_proxy(addon: OnionProxyAddon, state: dict) -> None:
    options = Options(listen_host=PROXY_HOST, listen_port=addon.proxy.port, confdir=str(MITMPROXY_DIR))
    master = DumpMaster(options, with_termlog=False, with_dumper=False)
    master.addons.add(addon)
    state["loop"] = asyncio.get_running_loop()
    state["master"] = master
    await master.run()


class DashboardController:
    def __init__(self, ignore_path: Path, blocklist_path: Path) -> None:
        self.ignore_path = ignore_path
        self.blocklist_path = blocklist_path
        self.events: queue.Queue = queue.Queue()
        self.state: dict = {}
        self.worker: threading.Thread | None = None
        self.proxy_running = False
        self.proxy_port: int | None = None
        self.pending: dict[str, PendingAlert] = {}
        self.alert_groups: dict[str, dict] = {}
        self.group_by_domain: dict[str, str] = {}
        self.addon: OnionProxyAddon | None = None
        self.sound_enabled = True
        self.observation_mode = bool(load_preferences().get("observation_mode", False))
        self.alerts: list[dict] = []
        self.activity: list[dict] = []
        self.last_error: str | None = None
        self.lock = threading.RLock()

    def start(self) -> dict:
        with self.lock:
            if self.worker and self.worker.is_alive():
                return {"ok": False, "message": "Защита уже запускается или включена."}
            try:
                port = find_available_port()
            except OSError as error:
                return {"ok": False, "message": str(error)}
            self.proxy_port = port
            self.last_error = None
            addon = OnionProxyAddon(
                UserCertificate(), WindowsProxySettings(port),
                load_ignored_domains(self.ignore_path), load_blocklist(self.blocklist_path), self.events,
            )
            addon.sound_enabled = self.sound_enabled
            addon.observation_mode = self.observation_mode
            self.addon = addon

            def worker() -> None:
                try:
                    asyncio.run(run_proxy(addon, self.state))
                except Exception as error:
                    self.events.put(("error", str(error)))
                finally:
                    addon.cleanup()
                    self.events.put(("status", "stopped", None))

            self.worker = threading.Thread(target=worker, name="OnionProxyWorker", daemon=True)
            self.worker.start()
            return {"ok": True, "message": "Защита запускается."}

    def stop(self) -> dict:
        self._drain_events()
        with self.lock:
            for alert in list(self.pending.values()):
                self._resolve(alert, "BLOCK")
            self.pending.clear()
            self.alerts.clear()
            self.alert_groups.clear()
            self.group_by_domain.clear()
            loop, master = self.state.get("loop"), self.state.get("master")
            if loop and master:
                loop.call_soon_threadsafe(master.shutdown)
            return {"ok": True, "message": "Защита останавливается."}

    def decide(self, alert_id: str, action: str) -> dict:
        self._drain_events()
        if action not in ("ALLOW", "BLOCK"):
            return {"ok": False, "message": "Unknown decision."}
        with self.lock:
            group = self.alert_groups.pop(alert_id, None)
            if group is None:
                return {"ok": False, "message": "This request is already closed."}
            self.group_by_domain.pop(group["domain"].lower(), None)
            self.alerts = [item for item in self.alerts if item["id"] != alert_id]
            for pending_id in group["pending_ids"]:
                alert = self.pending.pop(pending_id, None)
                if alert:
                    self._resolve(alert, action)
        return {"ok": True}

    def toggle_sound(self) -> dict:
        with self.lock:
            self.sound_enabled = not self.sound_enabled
            if self.addon:
                self.addon.sound_enabled = self.sound_enabled
            message = "Notification sound on." if self.sound_enabled else "Notification sound off."
            return {"ok": True, "sound_enabled": self.sound_enabled, "message": message}

    def toggle_observation(self) -> dict:
        with self.lock:
            self.observation_mode = not self.observation_mode
            if self.addon:
                self.addon.observation_mode = self.observation_mode
            save_preferences({"observation_mode": self.observation_mode})
            message = "Режим наблюдения включён: запросы не блокируются." if self.observation_mode else "Режим наблюдения выключен."
            return {"ok": True, "observation_mode": self.observation_mode, "message": message}

    def block_domain(self, alert_id: str) -> dict:
        self._drain_events()
        with self.lock:
            group = self.alert_groups.get(alert_id)
            if not group or group["count"] < 5:
                return {"ok": False, "message": "Available after five requests from this source."}
            domain = group["domain"].strip().lower().rstrip(".")
            labels = domain.split(".")
            if (len(labels) < 2 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                                      or not label.isascii() or not all(ch.isalnum() or ch == "-" for ch in label)
                                      for label in labels)):
                return {"ok": False, "message": "This address cannot be safely added to the blocklist."}
            rules = load_blocklist(self.blocklist_path)
            if not any(rule.host == domain and not rule.scheme and rule.port is None and not rule.path for rule in rules):
                with self.blocklist_path.open("a", encoding="utf-8") as block_file:
                    if self.blocklist_path.stat().st_size:
                        block_file.write("\n")
                    block_file.write(domain + "\n")
            if self.addon:
                self.addon.block_rules = load_blocklist(self.blocklist_path)
            self.alert_groups.pop(alert_id, None)
            self.group_by_domain.pop(domain, None)
            self.alerts = [item for item in self.alerts if item["id"] != alert_id]
            for pending_id in group["pending_ids"]:
                alert = self.pending.pop(pending_id, None)
                if alert:
                    self._resolve(alert, "BLOCK")
        return {"ok": True, "message": f"{domain} added to the blocklist; pending requests blocked."}

    @staticmethod
    def _resolve(alert: PendingAlert, action: str) -> None:
        def set_action() -> None:
            if not alert.future.done():
                alert.future.set_result(action)
        alert.loop.call_soon_threadsafe(set_action)

    def snapshot(self) -> dict:
        self._drain_events()
        with self.lock:
            alive = bool(self.worker and self.worker.is_alive())
            return {
                "running": self.proxy_running,
                "starting": alive and not self.proxy_running and self.last_error is None,
                "port": self.proxy_port,
                "ignore_path": str(self.ignore_path),
                "blocklist_path": str(self.blocklist_path),
                "alerts": list(self.alerts),
                "activity": list(self.activity),
                "error": self.last_error,
                "sound_enabled": self.sound_enabled,
                "observation_mode": self.observation_mode,
            }

    def _drain_events(self) -> None:
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            with self.lock:
                kind = event[0]
                if kind == "status":
                    _, status, port = event
                    self.proxy_running = status == "running"
                    if port:
                        self.proxy_port = port
                elif kind == "alert":
                    alert = event[1]
                    pending_id = uuid.uuid4().hex
                    self.pending[pending_id] = alert
                    domain_key = alert.domain.lower()
                    group_id = self.group_by_domain.get(domain_key)
                    group = self.alert_groups.get(group_id) if group_id else None
                    if group is None:
                        group_id = uuid.uuid4().hex
                        group = {"id": group_id, "domain": alert.domain, "url": alert.url,
                                 "findings": list(alert.findings), "evidence": list(alert.evidence),
                                 "application": alert.application, "count": 0, "pending_ids": []}
                        self.alert_groups[group_id] = group
                        self.group_by_domain[domain_key] = group_id
                        self.alerts.append(group)
                    group["count"] += 1
                    group["pending_ids"].append(pending_id)
                    group["findings"] = list(dict.fromkeys(group["findings"] + alert.findings))
                    evidence_keys = {(item.get("type"), item.get("value"), item.get("source")) for item in group["evidence"]}
                    for item in alert.evidence:
                        key = (item.get("type"), item.get("value"), item.get("source"))
                        if key not in evidence_keys and len(group["evidence"]) < 30:
                            group["evidence"].append(item)
                            evidence_keys.add(key)
                elif kind == "event":
                    _, time, action, domain, findings, evidence = event
                    entry = {"time": time, "action": action, "domain": domain,
                             "findings": findings, "evidence": evidence, "count": 1, "files": [
                                 finding[5:] for finding in findings if finding.startswith("FILE:")
                             ]}
                    self.activity.insert(0, entry)
                    del self.activity[100:]
                elif kind == "blocklist":
                    _, event_time, domain, url, rule, count = event
                    existing = next((item for item in self.activity if item.get("rule") and item["domain"] == domain), None)
                    if existing:
                        existing["time"] = event_time
                        existing["url"] = url
                        existing["count"] += count
                        self.activity.remove(existing)
                        self.activity.insert(0, existing)
                    else:
                        self.activity.insert(0, {
                            "time": event_time, "action": "BLOCK", "domain": domain,
                            "findings": ["BLOCKLIST"], "evidence": [
                                {"type": "URL", "value": url, "source": "заблокировано правилом"},
                            ], "files": [], "count": count, "rule": rule, "url": url,
                        })
                    del self.activity[100:]
                elif kind == "error":
                    self.last_error = event[1]


def load_dashboard() -> bytes:
    bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    path = bundle_dir / "ui" / "dashboard.html"
    if not path.is_file():
        path = Path(__file__).resolve().parent / "ui" / "dashboard.html"
    return path.read_bytes()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, controller: DashboardController, token: str) -> None:
        self.controller = controller
        self.token = token
        self.dashboard = load_dashboard()
        handler = type("OnionProxyHandler", (DashboardHandler,), {})
        super().__init__(("127.0.0.1", 0), handler)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, format: str, *args) -> None:
        return

    def _valid_path(self, api: str = "") -> bool:
        path = urlsplit(self.path).path
        return path == f"/{self.server.token}/" + api

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self._valid_path():
            body = self.server.dashboard
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self._valid_path("api/state"):
            self._send_json(self.server.controller.snapshot())
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if not urlsplit(self.path).path.startswith(f"/{self.server.token}/api/"):
            self.send_error(404)
            return
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc != f"127.0.0.1:{self.server.server_port}":
            self.send_error(403)
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 1024 * 1024)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"ok": False, "message": "Некорректный запрос."}, 400)
            return
        path = urlsplit(self.path).path.removeprefix(f"/{self.server.token}/api/")
        if path == "start":
            response = self.server.controller.start()
        elif path == "stop":
            response = self.server.controller.stop()
        elif path == "open-ignore-list":
            try:
                os.startfile(str(self.server.controller.ignore_path))
                response = {"ok": True}
            except OSError as error:
                response = {"ok": False, "message": str(error)}
        elif path == "open-blocklist":
            try:
                os.startfile(str(self.server.controller.blocklist_path))
                response = {"ok": True}
            except OSError as error:
                response = {"ok": False, "message": str(error)}
        elif path == "exit-app":
            response = self.server.controller.stop()

            def shutdown_after_proxy() -> None:
                worker = self.server.controller.worker
                if worker and worker.is_alive():
                    worker.join()
                self.server.shutdown()

            threading.Thread(target=shutdown_after_proxy, daemon=True).start()
        elif path == "decision":
            response = self.server.controller.decide(str(payload.get("id", "")), str(payload.get("action", "")))
        elif path == "block-domain":
            response = self.server.controller.block_domain(str(payload.get("id", "")))
        elif path == "toggle-sound":
            response = self.server.controller.toggle_sound()
        elif path == "toggle-observation":
            response = self.server.controller.toggle_observation()
        else:
            self.send_error(404)
            return
        self._send_json(response)


def main() -> int:
    if sys.platform != "win32":
        raise SystemExit("onion-proxy currently supports Windows only.")
    try:
        global _INSTANCE_MUTEX
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p)
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        # Keep the old mutex identifier so an already-running earlier build cannot overlap.
        _INSTANCE_MUTEX = kernel32.CreateMutexW(None, True, "Local\\SecurityBoxDesktopApp")
        if not _INSTANCE_MUTEX:
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == 183:
            ctypes.WinDLL("user32").MessageBoxW(None, "onion-proxy уже запущен.", "onion-proxy", 0x40)
            return 0

        ignore_path, blocklist_path = prepare_app_data()
        controller = DashboardController(ignore_path, blocklist_path)
        token = uuid.uuid4().hex
        server = DashboardServer(controller, token)
        url = f"http://127.0.0.1:{server.server_port}/{token}/"
        if not webbrowser.open(url):
            raise RuntimeError("Не удалось открыть панель. Откройте ссылку вручную: " + url)
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        if "controller" in locals():
            controller.stop()
    except Exception as error:
        ctypes.WinDLL("user32").MessageBoxW(None, str(error), "onion-proxy", 0x10)
        return 1
    finally:
        if "server" in locals():
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
