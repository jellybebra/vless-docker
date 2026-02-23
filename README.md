# vless-docker (x-ui + self-sni via docker compose)

This project now boots the whole stack using `docker compose` and performs the full self-sni automation flow.

## One-file install (image only, no build context)

Create a local `docker-compose.yml` with this content, change only `environment` values, then run `docker compose up -d`:

```yaml
services:
  vless:
    image: ghcr.io/jellybebra/vless-docker:latest
    container_name: vless-selfsni
    restart: unless-stopped
    environment:
      XUI_USERNAME: "admin"
      XUI_PASSWORD: "change_me"
      XUI_WEBPATH: "panelpath"
      SELF_SNI_DOMAIN: "example.com"
      SELF_SNI_PORT: "9000"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - ./data/xui:/etc/x-ui
      - ./data/letsencrypt:/etc/letsencrypt
      - ./data/www:/var/www/html
      - ./data/cert:/root/cert
```

## Container registry

- Image: `ghcr.io/jellybebra/vless-docker:latest`
- Auto-publish workflow: `.github/workflows/publish-ghcr.yml`
- Trigger: every push to `main`, every tag `v*`, and manual run from GitHub Actions UI.
- Cost: free for public images on GHCR.

If this is the very first publish and image does not exist yet, push `main` once (or run workflow manually), then set package visibility to `Public` in GitHub Packages.

## What is automated

On first container start, `docker/entrypoint.sh` does this:

1. Configures `x-ui` on `8080` with HTTP and your `XUI_USERNAME/XUI_PASSWORD/XUI_WEBPATH`.
2. Logs into panel API.
3. Creates inbound `443` (wizard-like) if it does not exist.
4. Disables inbound.
5. Configures `nginx` and requests certificate via `certbot`.
6. Downloads a random fake website (same source as `fakesite.sh`) into `/var/www/html`.
7. Sets inbound fields in this order: `dest=127.0.0.1:9000`, `serverNames=[SELF_SNI_DOMAIN]`, `xver=1`.
8. Calls `getNewX25519Cert`.
9. Saves inbound update and enables inbound back.

## Prerequisites

1. DNS `A` record for `SELF_SNI_DOMAIN` must point to your server.
2. Ports `80`, `443`, and `8080` must be reachable.
3. Docker + Docker Compose must be installed.

## Run

1. Edit `docker-compose.yml` and set your values in `services.vless.environment`:

```yaml
environment:
  XUI_USERNAME: "admin"
  XUI_PASSWORD: "change_me"
  XUI_WEBPATH: "panelpath"
  SELF_SNI_DOMAIN: "example.com"
  SELF_SNI_PORT: "9000"
```

2. Start:

```bash
docker compose up -d
```

3. Panel URL:

```text
http://<server-ip>:8080/<XUI_WEBPATH>
```

## Persistence

Data is persisted in local folders:

- `data/xui` -> `/etc/x-ui`
- `data/letsencrypt` -> `/etc/letsencrypt`
- `data/www` -> `/var/www/html`
- `data/cert` -> `/root/cert`

So restarts do not reset panel/inbound/certs.
