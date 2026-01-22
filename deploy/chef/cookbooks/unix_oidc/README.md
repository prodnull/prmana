# unix_oidc Cookbook

Chef cookbook for installing and configuring the unix-oidc PAM module for OIDC-based authentication on Unix/Linux systems.

## Requirements

### Platforms

- Ubuntu 20.04+
- Debian 11+
- Red Hat Enterprise Linux 8+
- Rocky Linux 8+

### Chef

- Chef Infra Client 15.0+

### Dependencies

None

## Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `node['unix_oidc']['version']` | String | `'latest'` | Version to install |
| `node['unix_oidc']['issuer']` | String | `nil` | OIDC issuer URL (required) |
| `node['unix_oidc']['client_id']` | String | `'unix-oidc'` | OIDC client ID |
| `node['unix_oidc']['install_agent']` | Boolean | `true` | Install oidc-agent |
| `node['unix_oidc']['enable_dpop']` | Boolean | `false` | Enable DPoP tokens |
| `node['unix_oidc']['pam_services']` | Array | `[]` | PAM services to configure |
| `node['unix_oidc']['install_dir']` | String | `'/opt/unix-oidc'` | Installation directory |
| `node['unix_oidc']['config_dir']` | String | `'/etc/unix-oidc'` | Configuration directory |
| `node['unix_oidc']['log_level']` | String | `'info'` | Log level |
| `node['unix_oidc']['cache_dir']` | String | `'/var/cache/unix-oidc'` | Token cache directory |
| `node['unix_oidc']['claim_mappings']` | Hash | `{}` | Custom claim mappings |
| `node['unix_oidc']['allowed_groups']` | Array | `[]` | Allowed groups |

## Usage

### Basic Usage

Include the default recipe in your node's `run_list` and set the required attributes:

```ruby
# In a role or environment
default_attributes(
  'unix_oidc' => {
    'issuer' => 'https://idp.example.com',
    'client_id' => 'my-app'
  }
)

run_list(
  'recipe[unix_oidc::default]'
)
```

### With PAM Configuration

Configure specific PAM services for OIDC authentication:

```ruby
default_attributes(
  'unix_oidc' => {
    'issuer' => 'https://idp.example.com',
    'pam_services' => ['sshd', 'sudo'],
    'enable_dpop' => true
  }
)
```

### Wrapper Cookbook

Create a wrapper cookbook for your organization:

```ruby
# cookbooks/myorg_unix_oidc/recipes/default.rb

node.default['unix_oidc']['issuer'] = 'https://idp.myorg.com'
node.default['unix_oidc']['client_id'] = 'unix-servers'
node.default['unix_oidc']['pam_services'] = ['sshd']
node.default['unix_oidc']['allowed_groups'] = ['developers', 'ops']

include_recipe 'unix_oidc::default'
```

### With Claim Mappings

Map custom claims to Unix attributes:

```ruby
default_attributes(
  'unix_oidc' => {
    'issuer' => 'https://idp.example.com',
    'claim_mappings' => {
      'username' => 'preferred_username',
      'groups' => 'custom_groups_claim'
    }
  }
)
```

### Install Only

To install without configuring:

```ruby
include_recipe 'unix_oidc::install'
```

### Configure Only

To configure an existing installation:

```ruby
include_recipe 'unix_oidc::configure'
```

## Recipes

### default

Includes both `install` and `configure` recipes.

### install

- Installs required packages (curl, jq)
- Downloads and runs the unix-oidc installer
- Creates necessary directories

### configure

- Deploys configuration file from template
- Configures PAM services if specified
- Sets up systemd service for oidc-agent

## Testing

```bash
# Run ChefSpec tests
chef exec rspec

# Run Test Kitchen
kitchen test
```

## License

Apache-2.0
