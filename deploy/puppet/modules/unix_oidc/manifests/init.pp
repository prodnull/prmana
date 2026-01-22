# @summary Install and configure unix-oidc PAM module
#
# This class manages the installation and configuration of the unix-oidc
# PAM module for OIDC-based authentication on Unix systems.
#
# @param issuer
#   The OIDC issuer URL (required).
#
# @param client_id
#   The OIDC client ID.
#
# @param version
#   The version of unix-oidc to install.
#
# @param install_agent
#   Whether to install the unix-oidc agent.
#
# @param enable_dpop
#   Whether to enable DPoP (Demonstration of Proof-of-Possession).
#
# @param pam_services
#   List of PAM services to configure for unix-oidc authentication.
#
# @example Basic usage
#   class { 'unix_oidc':
#     issuer => 'https://auth.example.com',
#   }
#
# @example Full configuration
#   class { 'unix_oidc':
#     issuer        => 'https://auth.example.com',
#     client_id     => 'my-client',
#     version       => '0.1.0',
#     install_agent => true,
#     enable_dpop   => true,
#     pam_services  => ['sshd', 'sudo'],
#   }
#
class unix_oidc (
  String $issuer,
  String $client_id = 'unix-oidc',
  String $version = 'latest',
  Boolean $install_agent = true,
  Boolean $enable_dpop = false,
  Array[String] $pam_services = [],
) {
  contain unix_oidc::install
  contain unix_oidc::config

  Class['unix_oidc::install']
  -> Class['unix_oidc::config']
}
