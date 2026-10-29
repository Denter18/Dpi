[app]

title = NoDPI v2.3
package.name = nodpi
package.domain = org.gvcoder

source.dir = .
source.include_exts = py
source.exclude_dirs = .git,.github,.buildozer,bin,java_src,tests,__pycache__
source.exclude_patterns = p4a_hook.py

version = 2.3.1

# Версии подобраны вместе: p4a v2024.01.21 = Python 3.11.5 + Kivy 2.3.0 + NDK 25b.
# Ветка master у p4a сейчас на Python 3.14 и Kivy 2.3.1, что не сочетается
# с kivy==2.3.0 и cython==0.29.36 из workflow.
requirements = python3,kivy==2.3.0,pyjnius

orientation = portrait
fullscreen = 0

android.permissions = INTERNET,ACCESS_NETWORK_STATE,FOREGROUND_SERVICE
android.api = 33
android.minapi = 24
android.ndk = 25b
android.ndk_api = 24
android.archs = arm64-v8a
android.accept_sdk_license = True

# Java-сервис VPN и хук, который добавляет его в AndroidManifest.xml
android.add_src = java_src

p4a.branch = v2024.01.21
p4a.hook = p4a_hook.py

# Путь android.sdk_path добавляется в CI (см. .github/workflows/build_apk.yml),
# локально buildozer скачает SDK сам.

[buildozer]

log_level = 2
warn_on_root = 0
