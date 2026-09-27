"""Keep mitmproxy's optional WinDivert backend code, but omit unused driver payloads."""

from PyInstaller.utils.hooks import collect_data_files


datas = collect_data_files(
    "pydivert.windivert_dll",
    excludes=["*.dll", "*.sys"],
)
