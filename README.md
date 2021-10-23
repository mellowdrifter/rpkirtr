# rpkirtr

Implements an RPKI-RTR server in Go. Supports most of RFC8210. Does not support version 0, only version 1.

Complile and run. Accepts connections over IPv4 and IPv6.

1. git clone https://github.com/mellowdrifter/rpkirtr.git
2. go get gopkg.in/ini.v1
3. go build \*.go
4. create [config.ini](https://github.com/mellowdrifter/rpkirtr/blob/master/config.ini)
5. ./rpkirtr

Point some clients to the server address, IPv4 or IPv6, and that's it.

Run it as a daemon for persistance.
