# unix_oidc

## Table of Contents

1. [Description](#description)
2. [Requirements](#requirements)
3. [Usage](#usage)
4. [Reference](#reference)
5. [Limitations](#limitations)
6. [License](#license)

## Description

This Puppet module installs and configures the unix-oidc PAM module for OIDC-based authentication on Unix systems. It provides a simple way to enable passwordless SSH and sudo authentication using OpenID Connect identity providers.

## Requirements

### Puppet

- Puppet 7.x or 8.x

### Operating Systems

- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- Red Hat Enterprise Linux 8, 9
- Rocky Linux 8, 9

### Dependencies

The module will automatically install the following packages:

- curl
- jq

## Usage

### Basic Usage

The minimum configuration requires only the OIDC issuer URL:

```puppet
class { 'unix_oidc':
  issuer => 'https://auth.example.com',
}
```

### Full Configuration

```puppet
class { 'unix_oidc':
  issuer        => 'https://auth.example.com',
  client_id     => 'my-unix-oidc-client',
  version       => '0.1.0',
  install_agent => true,
  enable_dpop   => true,
  pam_services  => ['sshd', 'sudo'],
}
```

### Using Hiera

You can also configure the module using Hiera:

```yaml
# data/common.yaml
unix_oidc::issuer: 'https://auth.example.com'
unix_oidc::client_id: 'unix-oidc'
unix_oidc::version: 'latest'
unix_oidc::install_agent: true
unix_oidc::enable_dpop: true
unix_oidc::pam_services:
  - 'sshd'
  - 'sudo'
```

Then include the class in your manifests:

```puppet
include unix_oidc
```

## Reference

### Class: unix_oidc

Main class for installing and configuring unix-oidc.

#### Parameters

##### `issuer`

**Required.** The OIDC issuer URL.

Type: `String`

Example: `'https://auth.example.com'`

##### `client_id`

The OIDC client ID used for authentication.

Type: `String`

Default: `'unix-oidc'`

##### `version`

The version of unix-oidc to install. Use `'latest'` for the most recent release.

Type: `String`

Default: `'latest'`

##### `install_agent`

Whether to install the unix-oidc agent for token management.

Type: `Boolean`

Default: `true`

##### `enable_dpop`

Whether to enable DPoP (Demonstration of Proof-of-Possession) for enhanced token security.

Type: `Boolean`

Default: `false`

##### `pam_services`

List of PAM services to configure for unix-oidc authentication. Common values include `'sshd'` and `'sudo'`.

Type: `Array[String]`

Default: `[]`

### Private Classes

#### unix_oidc::install

Handles the installation of unix-oidc and its dependencies.

#### unix_oidc::config

Manages the configuration files and PAM service integration.

### Defined Types

#### unix_oidc::config::pam_service

Configures a specific PAM service to use unix-oidc authentication.

##### Parameters

- `service_name`: The name of the PAM service (defaults to the resource title)

## Limitations

- The module assumes network access to download the unix-oidc installer from GitHub releases
- PAM service configuration uses a simple sed-based approach; for complex PAM configurations, consider managing PAM files directly
- The module does not manage the OIDC identity provider configuration

## License

Apache-2.0
