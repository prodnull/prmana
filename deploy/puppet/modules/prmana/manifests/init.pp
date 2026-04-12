# @summary Install and configure prmana PAM module
#
# This class manages the installation and configuration of the prmana
# PAM module for OIDC-based authentication on Unix systems.
#
# @param issuer
#   The OIDC issuer URL (required).
#
# @param client_id
#   The OIDC client ID.
#
# @param version
#   The version of prmana to install.
#
# @param install_agent
#   Whether to install the prmana agent.
#
# @param enable_dpop
#   Whether to enable DPoP (Demonstration of Proof-of-Possession).
#
# @param pam_services
#   List of PAM services to configure for prmana authentication.
#
# @example Basic usage
#   class { 'prmana':
#     issuer => 'https://auth.example.com',
#   }
#
# @example Full configuration
#   class { 'prmana':
#     issuer        => 'https://auth.example.com',
#     client_id     => 'my-client',
#     version       => '0.1.0',
#     install_agent => true,
#     enable_dpop   => true,
#     pam_services  => ['sshd', 'sudo'],
#   }
#
class prmana (
  String $issuer,
  String $client_id = 'prmana',
  String $version = 'latest',
  Boolean $install_agent = true,
  Boolean $enable_dpop = false,
  Array[String] $pam_services = [],
) {
  contain prmana::install
  contain prmana::config

  Class['prmana::install']
  -> Class['prmana::config']
}
