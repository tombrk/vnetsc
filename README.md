# vnetsc (vNet Secure Containers)

gVisor based container runtime that filters the network.

Socket syscalls are systrapped. reads/writes are filtered:
- DNS: permitted
- HTTP/1.1: redirected to proxying in-process http.Server
- HTTPS/1.1: TLS terminated using on-the-fly cert, redirected through in-process http.Server

This in-process http.Server can rewrite / inspect / etc. any HTTP request at L7 level.

## Building

```
CGO_ENABLED=0 go build .
```

## Running

This works only on Linux.

```
sudo podman run --runtime $PWD/vnetsc -it alpine
```
