"""Aegis uses regular proxy mode; the transparent-mode driver is not bundled."""

from PyInstaller.utils.hooks import collect_data_files


datas = collect_data_files(
    "mitmproxy_windows",
    excludes=["*.dll", "*.sys", "*.lib"],
)
