
<img width="64" height="64" alt="logo" src="https://github.com/user-attachments/assets/9390e061-f9fe-4a2f-b3e9-2bded98467a0" />

# iCloudPD Web UI (icloudpd-webui)

A lightweight web interface for managing automated iCloud Photos downloads (via `icloudpd`) across one or more configured iCloud accounts and policies. The application provides a browser-based workflow to authenticate accounts (including 2FA), configure download options, run maintenance actions, and inspect logs without having to operate directly on the host shell.

## Key capabilities

- Manage multiple iCloud accounts and their download settings stored in a database
- Initialize accounts with 2FA and reuse existing session cookies
- Run operational actions from the UI (restart, mount handling, housekeeping)
- Stream and review command logs from the browser
- Manage Web UI application users (admin/user), including edit and password reset (if enabled in your build)

---

## Requirements

- Docker Engine + Docker Compose (v2)
- A Linux host (recommended) with persistent storage available for:
  - application data
  - iCloudPD cookie/session files
  - downloaded photos/videos

---

## Quick start (Docker Compose with PostgreSQL container)

### 1) Folder structure

Create a working directory, for example:

```
icloudpd-webui/
  docker-compose.yml
  .env
  data/
    downloads/
    icloudpd/
  postgres/
```

Suggested meanings:
- `./data/downloads` – where photos/videos are stored
- `./data/icloudpd` – where iCloudPD cookies/sessions live (persistent)
- `./postgres` – PostgreSQL data directory (persistent)

---

## Example `docker-compose.yml` (PostgreSQL in a container)

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: icloudpd_postgres
    environment:
      POSTGRES_DB: icloudpd_webui
      POSTGRES_USER: icloudpd
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - ./postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U icloudpd -d icloudpd_webui"]
      interval: 10s
      timeout: 5s
      retries: 10
    restart: unless-stopped

  icloudpd-webui:
    image: icloudpd-webui:latest
    # If you build locally, replace the image line with:
    # build: .
    container_name: icloudpd_webui
    depends_on:
      postgres:
        condition: service_healthy
    env_file: .env
    environment:
      - PORT=8090
      - TZ=${TZ:-Europe/Bucharest}
      - DATABASE_URL=${DATABASE_URL}
      - MASTER_KEY=${MASTER_KEY}
      - TRUST_PROXY_COUNT=${TRUST_PROXY_COUNT:-0}
      - ICLOUDPD_IMAGE=${ICLOUDPD_IMAGE:-boredazfcuk/icloudpd:latest}
    ports:
      - "${APP_HTTP_PORT}:3000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./hostdata:/hostdata
    restart: unless-stopped
```

Notes:
- The container’s internal port is assumed to be `3000`. If your build uses a different port internally, adjust the right-hand side of the port mapping.
- If your project uses different volume paths internally, adapt the right side accordingly.

---

## Example `.env`

Create a `.env` file alongside `docker-compose.yml`:

```dotenv
# Web UI port exposed on the host
APP_HTTP_PORT=8080

# PostgreSQL container password (used by the postgres service)
POSTGRES_PASSWORD=ChangeMeStrong

# App DB connection string (used by the webui service)
DATABASE_URL=postgresql://icloudpd:ChangeMeStrong@postgres:5432/icloudpd_ui
TZ=Europe/Bucharest
TRUST_PROXY_COUNT=0
ICLOUDPD_IMAGE=boredazfcuk/icloudpd:latest

# Optional: break-glass admin password reset token
# Use a long random string (hex/base64/url-safe). Not required to be base64.
ADMIN_RESET_TOKEN=replace-with-long-random-token
```

Security recommendations:
- Use a strong `POSTGRES_PASSWORD`.
- Do not reuse your iCloud password anywhere else.
- Keep `.env` private (do not commit it).

---

## Installation and first run

### 1) Start the stack

From the folder containing `docker-compose.yml`:

```bash
docker compose up -d
```

Check logs:

```bash
docker compose logs -f icloudpd-webui
```

### 2) Open the Web UI

Navigate to:

- `http://<your-host>:8080` (or your chosen `APP_HTTP_PORT`)

### 3) Create / sign in as admin (depending on your build)

If your build initializes a default admin or includes a registration flow, follow the on-screen prompts.

If you enabled `ADMIN_RESET_TOKEN`, you can recover admin access using the “Forgot admin password?” flow from the login page (if present in your build).

---

## Using the UI actions

The UI includes operational buttons that trigger server-side commands. The names may vary slightly by build, but the purpose is as follows.

### Ensure container
Purpose:
- Verifies the runtime prerequisites are present for the selected policy/account.
- Commonly used after reboots, upgrades, or when an account/policy appears “stuck.”

Typical outcome:
- Confirms required folders, permissions, and runtime state are ready before executing downloads.

When to use:
- After updating the app.
- After changing download paths.
- If a policy fails immediately with missing path/session errors.

---

### Fix skip dates
Purpose:
- Runs a maintenance task that corrects/normalizes “skip date” logic used by the downloader.
- Helpful if you changed time ranges, filters, or had partial runs that caused unintended skipping.

Typical outcome:
- The system recalculates/repairs “skip date” state so subsequent runs behave correctly.

When to use:
- After modifying date-related settings.
- If you see items being skipped incorrectly.

---

### Restart
Purpose:
- Restarts the background components or the service logic used for downloads/operations.

Typical outcome:
- Clears transient runtime issues and reloads configuration from the database.

When to use:
- After making multiple configuration changes.
- After a long-running session becomes unresponsive.

---

### Create `.mounted`
Purpose:
- Creates a marker file commonly used by iCloudPD setups to indicate a download directory is mounted and safe to write to.

Typical outcome:
- Prevents downloads from writing into an unmounted path (for example, if an external drive or network share is offline).

When to use:
- If your downloads path is a bind mount (NFS/SMB/USB) and your workflow requires a mount guard.

Important:
- This does not mount drives by itself; it only places the marker file used by your operational logic.

---

### Initialise (2FA)
Purpose:
- Starts the iCloud authentication flow for a selected iCloud account, including Apple’s two-factor authentication.

Typical outcome:
- Creates/updates cookie/session files for that account.
- After completion, the account should be able to run downloads without prompting for 2FA again until the session expires.

When to use:
- On first setup for an account.
- After Apple invalidates sessions/cookies.
- If the UI shows an account as unauthenticated.

---

### Open terminal
Purpose:
- Opens a browser-based terminal session to view or interact with the runtime environment.

Typical outcome:
- Allows you to run diagnostics commands, inspect directories, or validate connectivity without SSHing into the host separately.

When to use:
- Troubleshooting.
- Checking file paths/permissions.
- Verifying mounts or cookie files.

---

### View log buttons
Purpose:
- Opens logs for previously executed operations, typically per policy/account/action.

Typical outcome:
- You can review command output, errors, and completion status.
- Useful for confirming that maintenance actions (like “Fix skip dates”) actually ran and finished.

When to use:
- After any action completes to verify success.
- When a task fails to identify the exact error.

---

## Typical “make it work” workflow (recommended)

1) Deploy the stack (`docker compose up -d`)
2) Log into the Web UI
3) Add an iCloud account and configure the download path
4) Run **Ensure container**
5) Run **Initialise (2FA)** and complete Apple 2FA prompts
6) If you use a mounted download location, ensure it is mounted and then run **Create `.mounted`**
7) Start a download/run operation
8) Use **View log** to verify it executed correctly
9) If you adjust date filters later, run **Fix skip dates**, then verify via logs
10) Use **Restart** after major configuration changes or upgrades

---

## Troubleshooting

### PostgreSQL authentication failed (28P01)
This indicates the app cannot authenticate to Postgres.

Checklist:
- Confirm `DATABASE_URL` matches the Postgres service credentials.
- If you changed `POSTGRES_PASSWORD` after the DB volume already existed, the password inside Postgres did not change automatically. Update it with:
  ```bash
  docker compose exec postgres psql -U postgres -d postgres -c "ALTER USER icloudpd WITH PASSWORD 'NewPasswordHere';"
  ```
  Then update `.env` accordingly and restart the app.

### Buttons overflow on small screens
If action buttons appear outside panels on mobile, ensure your build includes scroll wrapping (`.table-wrap`) or card layout conversion for tables.

---

## License / notes
This README describes operational behavior at a functional level. Exact button names, internal command implementations, and volume paths may differ by build. Adjust the compose paths and ports to your environment.
