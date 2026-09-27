# onion-proxy

Скачать программу для Windows можно в разделе Releases.



onion-proxy is a small Windows app that helps you see some of the data programs send over the internet. It routes supported requests through a local proxy and can warn you when it spots things like a phone number, email address, or password. You can allow or block a request from the browser dashboard.

You can also keep a list of sites that should always be blocked and a list of sites that should be skipped. The dashboard and proxy run on your computer.

## Getting started

Download the files in `release-onion-proxy`, start `onion-proxy.exe`, and turn protection on from the browser dashboard. When you are done, use the dashboard's stop-and-exit button so Windows proxy settings are restored.

## A note about HTTPS and coverage

To inspect supported HTTPS requests, onion-proxy temporarily adds a local certificate for your Windows user. It removes the certificate and restores the previous proxy settings when you stop the app normally. Some apps bypass the system proxy or reject its certificate, so their traffic may not appear or may fail to connect.

onion-proxy is not an antivirus and cannot detect every threat or every way data can leave a computer. It only checks requests that pass through the proxy and whose contents it can read.

## Building from source

Run `build.ps1` in PowerShell. The script creates `.build-venv`, installs the packages listed in `requirements-build.txt`, and puts the Windows executable in `release-onion-proxy`.
