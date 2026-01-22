# unix-oidc Demo Vagrant Image

A complete demo environment with Keycloak IdP and unix-oidc, ready to explore OIDC-based Unix authentication. Works offline after first boot.

## Prerequisites

- [Vagrant](https://www.vagrantup.com/downloads) (2.3+)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (6.1+)
- 4GB+ available RAM (Keycloak requirement)

## Quick Start

```bash
# Clone the repository (if not already done)
git clone https://github.com/prodnull/unix-oidc.git
cd unix-oidc/deploy/vagrant/demo

# Start the VM (first boot takes 5-10 minutes to download and start Keycloak)
vagrant up

# SSH into the VM
vagrant ssh
```

## What's Included

- Ubuntu 22.04 LTS base
- Docker with Keycloak 23.0
- unix-oidc pre-configured for local Keycloak
- Three test users with passwords
- Helper scripts for token operations
- Works offline after first boot (Docker images cached)

## Services

| Service   | URL                           | Credentials      |
|-----------|-------------------------------|------------------|
| Keycloak  | http://localhost:8080         | admin / admin    |
| SSH       | localhost:2222                | See test users   |

## Test Users

Pre-configured in both Keycloak and as local Unix users:

| Username  | Password   | Email                  |
|-----------|------------|------------------------|
| testuser  | testpass   | testuser@example.com   |
| adminuser | adminpass  | adminuser@example.com  |
| demouser  | demopass   | demouser@example.com   |

## Testing

### Get an Access Token

```bash
# Inside the VM
vagrant ssh

# Get a token for testuser
get-oidc-token testuser testpass

# Or specify different user
get-oidc-token adminuser adminpass
```

### Decode and Inspect Token

```bash
# Get and decode a token
TOKEN=$(get-oidc-token testuser testpass)
decode-jwt $TOKEN
```

### View OIDC Discovery Document

```bash
curl -s http://localhost:8080/realms/unix-oidc-demo/.well-known/openid-configuration | jq
```

### Test Token via Keycloak API

```bash
# Get token
TOKEN=$(get-oidc-token testuser testpass)

# Validate token via userinfo endpoint
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/realms/unix-oidc-demo/protocol/openid-connect/userinfo | jq
```

## Accessing Keycloak Admin Console

1. Open http://localhost:8080/admin in your browser
2. Login with `admin` / `admin`
3. Select "unix-oidc-demo" realm from the dropdown

From the admin console you can:
- View and manage test users
- Inspect client configuration
- View authentication events
- Configure MFA policies

## Configuration Files

| Path | Description |
|------|-------------|
| `/etc/unix-oidc/config.env` | unix-oidc configuration (pre-configured) |
| `/opt/keycloak/docker-compose.yml` | Keycloak Docker Compose file |
| `/opt/keycloak/realm-export.json` | Keycloak realm configuration |

## Network Ports

| Port (Host) | Port (Guest) | Service      |
|-------------|--------------|--------------|
| 2222        | 22           | SSH          |
| 8080        | 8080         | Keycloak     |

## Helper Scripts

### get-oidc-token

Get an access token from the local Keycloak instance.

```bash
# Usage
get-oidc-token [username] [password]

# Examples
get-oidc-token                    # Uses testuser/testpass
get-oidc-token adminuser adminpass
```

### decode-jwt

Decode and display JWT token header and payload.

```bash
# Usage
decode-jwt <token>

# Example
TOKEN=$(get-oidc-token)
decode-jwt $TOKEN
```

## Docker Management

```bash
# View Keycloak logs
cd /opt/keycloak && docker compose logs -f

# Restart Keycloak
cd /opt/keycloak && docker compose restart

# Stop Keycloak
cd /opt/keycloak && docker compose down

# Start Keycloak
cd /opt/keycloak && docker compose up -d
```

## Vagrant Commands

```bash
# Start/provision the VM
vagrant up

# SSH into the VM
vagrant ssh

# Restart the VM
vagrant reload

# Stop the VM (preserves state)
vagrant halt

# Destroy the VM (removes all data)
vagrant destroy
```

## Offline Usage

After the first `vagrant up`, all Docker images are cached locally. The VM will work completely offline for subsequent boots.

To verify offline capability:
```bash
# Stop the VM
vagrant halt

# Disconnect from network (optional - for testing)

# Start the VM
vagrant up

# Keycloak should start from cached images
```

## Troubleshooting

### Keycloak Not Starting

```bash
# Check Keycloak container status
cd /opt/keycloak && docker compose ps

# View Keycloak logs
cd /opt/keycloak && docker compose logs keycloak

# Restart Keycloak
cd /opt/keycloak && docker compose restart
```

### Token Request Failing

```bash
# Check Keycloak is healthy
curl -s http://localhost:8080/health/ready | jq

# Verify realm exists
curl -s http://localhost:8080/realms/unix-oidc-demo | jq

# Check realm discovery
curl -s http://localhost:8080/realms/unix-oidc-demo/.well-known/openid-configuration | jq
```

### Not Enough Memory

The demo VM requires 4GB RAM. If you encounter memory issues:

1. Close other applications
2. Increase VirtualBox memory allocation in Vagrantfile
3. Use a machine with more RAM

### Port Conflicts

If ports 2222 or 8080 are in use:

```bash
# Check what's using the port
lsof -i :8080

# Edit Vagrantfile to use different ports
# Then reload the VM
vagrant reload
```

## Security Notes

- This environment is for **demo and testing only**
- Default passwords are intentionally weak
- Keycloak runs in dev mode with SSL disabled
- Do not expose these services to the internet
- Do not use this configuration in production

## Next Steps

1. Explore the [minimal image](../minimal/) for BYOIDP setup
2. Follow the [5-minute demo guide](../../quickstart/5-minute-demo.md)
3. Read the [15-minute production guide](../../quickstart/15-minute-production.md)
4. Configure your own IdP using [IdP templates](../../idp-templates/)
