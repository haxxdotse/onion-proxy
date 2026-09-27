"""Bundle the regular proxy helper without transparent-mode driver binaries."""

from PyInstaller.utils.hooks import collect_data_files


hiddenimports = ["mitmproxy_windows"]
datas = collect_data_files(
    "mitmproxy_windows",
    excludes=["*.dll", "*.sys", "*.lib"],
)
