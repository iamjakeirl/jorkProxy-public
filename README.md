# jorkProxy

A SOCKS5 client for Android 9.0+ (API 28), based on
[SocksDroid](https://github.com/bndeff/socksdroid) and the original
[PeterCxy/SocksDroid](https://github.com/PeterCxy/SocksDroid).

jorkProxy uses Android VpnService and tun2socks to forward TCP traffic through
one SOCKS5 server. It supports username/password authentication, profiles,
per-app routing, IPv6, boot connection, and automatic helper-process recovery.
UDP forwarding requires a compatible badvpn-udpgw server and must be enabled
separately; DNS works without enabling UDP forwarding.

## Setup

Enter your SOCKS5 server address and port, enable authentication if needed,
and turn on the proxy. Android will request VPN permission. Advanced settings
let you choose a DNS resolver, routing mode, and apps to include or bypass.
The DNS resolver must support TCP at the configured port (normally 53).
DNS queries handled by the app go through the same SOCKS5 server, with no
direct DNS fallback. A hostname used for the SOCKS server itself still needs
an initial system DNS lookup; use a numeric server IP to avoid that lookup.

For blocking traffic while the VPN is unavailable, enable Android's Always-on
VPN and Block connections without VPN settings. A running helper process does
not prove the remote proxy is reachable. Apps excluded from the VPN and
routes excluded by the selected routing mode are outside proxy coverage.

SOCKS5 does not encrypt the connection to your proxy, including password
authentication. Use a trusted network or a separately secured transport to the
proxy; HTTPS traffic retains its own encryption. See [PRIVACY.md](PRIVACY.md).

## Build and test

Use JDK 17 and an Android SDK with platform 31 and Build Tools 30.0.3. Set
`ANDROID_HOME` to the SDK directory or put `sdk.dir` in your untracked
`local.properties` file. Then run:

```sh
./gradlew :app:assembleDebug :app:lintDebug
bash tests/run.sh
```

The socket regression tests run against a local fake SOCKS server; they do
not require a device or external proxy. Testing VPN routing, network changes,
and helper recovery on Android still requires a device or emulator.

Native binaries for ARMv7, ARM64, x86 and x86_64 are included under
`app/src/main/jniLibs`. They are packaged by Gradle, not rebuilt by the command
above. Native sources and the existing NDK build script are under
`app/src/main`; rebuilding them requires an Android NDK and `ndk-build` on PATH.
Build outputs and signing keys must stay untracked. Release APKs should be
built from the intended source revision and distributed separately.

## License

See [LICENSE](LICENSE) and the license notices in the bundled native sources.
