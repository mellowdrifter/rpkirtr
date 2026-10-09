# ⚠️ ARCHIVED REPOSITORY

> [!WARNING]
> This repository is **archived and no longer maintained**.
> It has been superseded by [**`rpkirtr2`**](https://github.com/mellowdrifter/rpkirtr2), which provides RPKI-RTR v2, ASPA support, gRPC telemetry, and active production deployment.

# rpkirtr (v1)

Complile and run. Accepts connections over IPv4 and IPv6.

1. git clone https://github.com/mellowdrifter/rpkirtr.git
2. go get gopkg.in/ini.v1
3. go build \*.go
4. create [config.ini](https://github.com/mellowdrifter/rpkirtr/blob/master/config.ini)
5. ./rpkirtr

Point some clients to the server address, IPv4 or IPv6, and that's it.

Run it as a daemon for persistance.
