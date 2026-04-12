# prmana Cookbook

Chef cookbook for installing and configuring the prmana PAM module for OIDC-based authentication on Unix/Linux systems.

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
| `node["prmana']['version']` | String | `'latest'` | Version to install |
| `node["prmana']['issuer']` | String | `nil` | OIDC issuer URL (required) |
| `node["prmana']['client_id']` | String | `'prmana'` | OIDC client ID |
| `node["prmana']['install_agent']` | Boolean | `true` | Install oidc-agent |
| `node["prmana']['enable_dpop']` | Boolean | `false` | Enable DPoP tokens |
| `node["prmana']['pam_services']` | Array | `[]` | PAM services to configure |
| `node["prmana']['install_dir']` | String | `'/opt/prmana'` | Installation directory |
| `node["prmana']['config_dir']` | String | `'/etc/prmana'` | Configuration directory |
| `node["prmana']['log_level']` | String | `'info'` | Log level |
| `node["prmana']['cache_dir']` | String | `'/var/cache/prmana'` | Token cache directory |
| `node["prmana']['claim_mappings']` | Hash | `{}` | Custom claim mappings |
| `node["prmana']['allowed_groups']` | Array | `[]` | Allowed groups |

## Usage

### Basic Usage

Include the default recipe in your node's `run_list` and set the required attributes:

```ruby
# In a role or environment
default_attributes(
  'prmana' => {
    'issuer' => 'https://idp.example.com',
    'client_id' => 'my-app'
  }
)

run_list(
  'recipe[prmana::default]'
)
```

### With PAM Configuration

Configure specific PAM services for OIDC authentication:

```ruby
default_attributes(
  'prmana' => {
    'issuer' => 'https://idp.example.com',
    'pam_services' => ['sshd', 'sudo'],
    'enable_dpop' => true
  }
)
```

### Wrapper Cookbook

Create a wrapper cookbook for your organization:

```ruby
# cookbooks/myorg_prmana/recipes/default.rb

node.default['prmana']['issuer'] = 'https://idp.myorg.com'
node.default['prmana']['client_id'] = 'unix-servers'
node.default['prmana']['pam_services'] = ['sshd']
node.default['prmana']['allowed_groups'] = ['developers', 'ops']

include_recipe 'prmana::default'
```

### With Claim Mappings

Map custom claims to Unix attributes:

```ruby
default_attributes(
  'prmana' => {
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
include_recipe 'prmana::install'
```

### Configure Only

To configure an existing installation:

```ruby
include_recipe 'prmana::configure'
```

## Recipes

### default

Includes both `install` and `configure` recipes.

### install

- Installs required packages (curl, jq)
- Downloads and runs the prmana installer
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
