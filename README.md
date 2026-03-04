# vnetsc (vNet Secure Containers)

gVisor based container runtime that filters the network.

Socket syscalls are systrapped. reads/writes are filtered:
- DNS: permitted
- HTTP/1.1: redirected to proxying in-process http.Server
- HTTPS/1.1: TLS terminated using on-the-fly cert, redirected through in-process http.Server

This in-process http.Server can rewrite / inspect / etc. any HTTP request at L7 level.

## Secret Injection

vnetsc can inject secrets (e.g. API keys) into outbound HTTP requests at the proxy layer, so that containers never see the real secret value.

### How it works

1. You declare secrets via OCI container annotations with the prefix `vnetsc.test/secrets/`.
2. vnetsc reads these annotations from the OCI spec at startup.
3. For each secret, a deterministic placeholder value (`vnetsc-placeholder-<name>`) is generated.
4. Inside the container, the environment variable holds the **placeholder**, not the real key.
5. When the in-process HTTP proxy sees an outbound request to the secret's configured URL with `Authorization: Bearer <placeholder>`, it transparently replaces it with the real secret value.

The container code uses the env var as if it were a real API key — the swap happens at L7 inside the runtime, invisible to the guest.

### Annotation format

```
vnetsc.test/secrets/<name>=url=<target_url> env=<ENV_VAR> value=<real_secret> [type=bearer]
```

| Field   | Required | Description                                           |
|---------|----------|-------------------------------------------------------|
| `url`   | yes      | URL prefix to match (e.g. `https://api.anthropic.com`)|
| `env`   | yes      | Environment variable name exposed in the container    |
| `value` | yes      | The real secret value                                 |
| `type`  | no       | Auth type (default: `bearer`)                         |

### Example

```
sudo podman run \
  --runtime $PWD/vnetsc \
  --annotation vnetsc.test/secrets/anthropic="url=https://api.anthropic.com env=ANTHROPIC_API_KEY value=sk-ant-real-key type=bearer" \
  -e ANTHROPIC_API_KEY=vnetsc-placeholder-anthropic \
  -it alpine
```

Inside the container, `$ANTHROPIC_API_KEY` is `vnetsc-placeholder-anthropic`. When the container makes an HTTPS request to `api.anthropic.com` with `Authorization: Bearer vnetsc-placeholder-anthropic`, vnetsc rewrites the header to `Authorization: Bearer sk-ant-real-key` before forwarding upstream.

## Building

```
CGO_ENABLED=0 go build .
```

## Running

This works only on Linux.

```
sudo podman run --runtime $PWD/vnetsc -it alpine
```
