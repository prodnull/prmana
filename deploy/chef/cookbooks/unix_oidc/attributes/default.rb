# unix-oidc cookbook attributes
#
# Required attributes:
#   node['unix_oidc']['issuer'] - OIDC issuer URL (must be set)
#
# Optional attributes with defaults:

# Version of unix-oidc to install ('latest' or specific version)
default['unix_oidc']['version'] = 'latest'

# OIDC issuer URL (required - must be set in wrapper cookbook or role)
default['unix_oidc']['issuer'] = nil

# OIDC client ID
default['unix_oidc']['client_id'] = 'unix-oidc'

# Install the oidc-agent for token management
default['unix_oidc']['install_agent'] = true

# Enable DPoP (Demonstrating Proof of Possession) tokens
default['unix_oidc']['enable_dpop'] = false

# PAM services to configure (e.g., ['sshd', 'sudo'])
default['unix_oidc']['pam_services'] = []

# Installation directory
default['unix_oidc']['install_dir'] = '/opt/unix-oidc'

# Configuration directory
default['unix_oidc']['config_dir'] = '/etc/unix-oidc'

# Log level (debug, info, warn, error)
default['unix_oidc']['log_level'] = 'info'

# Token cache directory
default['unix_oidc']['cache_dir'] = '/var/cache/unix-oidc'

# Custom claim mappings (optional)
default['unix_oidc']['claim_mappings'] = {}

# Allowed groups (empty means all groups allowed)
default['unix_oidc']['allowed_groups'] = []
