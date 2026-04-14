# prmana cookbook attributes
#
# Required attributes:
#   node['prmana']['issuer'] - OIDC issuer URL (must be set)
#
# Optional attributes with defaults:

# Version of prmana to install ('latest' or specific version)
default['prmana']['version'] = 'latest'

# OIDC issuer URL (required - must be set in wrapper cookbook or role)
default['prmana']['issuer'] = nil

# OIDC client ID
default['prmana']['client_id'] = 'prmana'

# Install the prmana-agent for token management
default['prmana']['install_agent'] = true

# Enable DPoP (Demonstrating Proof of Possession) tokens
default['prmana']['enable_dpop'] = false

# PAM services to configure (e.g., ['sshd', 'sudo'])
default['prmana']['pam_services'] = []

# Installation directory
default['prmana']['install_dir'] = '/opt/prmana'

# Configuration directory
default['prmana']['config_dir'] = '/etc/prmana'

# Log level (debug, info, warn, error)
default['prmana']['log_level'] = 'info'

# Token cache directory
default['prmana']['cache_dir'] = '/var/cache/prmana'

# Custom claim mappings (optional)
default['prmana']['claim_mappings'] = {}

# Allowed groups (empty means all groups allowed)
default['prmana']['allowed_groups'] = []
