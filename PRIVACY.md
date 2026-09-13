# Privacy policy for jorkProxy

jorkProxy forwards the traffic covered by its routing and per-app settings to
a SOCKS5 server you configure. It contains no developer analytics or telemetry.
The proxy operator can observe destination addresses and read unencrypted
traffic. SOCKS5 itself does not encrypt traffic or username/password
authentication between your device and the proxy. HTTPS connections retain
their own encryption.

DNS requests handled by jorkProxy are sent over TCP through your SOCKS5 server
to your configured DNS resolver. There is no direct resolver fallback when
the proxy fails. The resolver can see the queried names, and the proxy can
observe unencrypted DNS. If you enter a hostname for the SOCKS server, Android
may resolve that hostname before connecting; a numeric IP avoids this lookup.
Apps and destinations excluded from proxy routing are outside this coverage.

Profiles, proxy credentials, the DNS cache, and connection status are stored in
the app's private Android storage. Credentials are not separately encrypted
at rest. App backup is disabled, and preferences and private files are excluded
from Android cloud backup and device-transfer rules. This does not remove
backups made by older versions. Uninstalling the app removes its private data.
Debug builds may log the proxy address and connection diagnostics.

Only use proxy servers and DNS resolvers you trust. Android's Block connections
without VPN setting can prevent traffic from escaping while the VPN is down.
