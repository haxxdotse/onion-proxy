"""Collect mitmproxy_rs itself without the unused transparent Windows redirector."""

from PyInstaller.utils.hooks import collect_data_files


datas = collect_data_files("mitmproxy_rs")
hiddenimports = []
