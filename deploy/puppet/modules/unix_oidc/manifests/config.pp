# @summary Configure unix-oidc
#
# This class manages the configuration of unix-oidc including the
# environment configuration file and PAM service integration.
#
# @api private
#
class unix_oidc::config {
  assert_private()

  # Ensure configuration directory exists
  file { '/etc/unix-oidc':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # Generate configuration file from template
  file { '/etc/unix-oidc/config.env':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp('unix_oidc/config.env.epp', {
      'issuer'      => $unix_oidc::issuer,
      'client_id'   => $unix_oidc::client_id,
      'enable_dpop' => $unix_oidc::enable_dpop,
    }),
    require => File['/etc/unix-oidc'],
  }

  # Configure PAM services if specified
  if !empty($unix_oidc::pam_services) {
    $unix_oidc::pam_services.each |String $service| {
      unix_oidc::config::pam_service { $service: }
    }
  }
}

# @summary Configure a PAM service for unix-oidc
#
# @param service_name
#   The name of the PAM service to configure.
#
define unix_oidc::config::pam_service (
  String $service_name = $title,
) {
  $pam_config_file = "/etc/pam.d/${service_name}"
  $pam_oidc_line = 'auth sufficient pam_oidc.so'

  # Only add the PAM line if the service file exists and doesn't already have it
  exec { "configure-pam-${service_name}":
    command => "/bin/sed -i '1a ${pam_oidc_line}' ${pam_config_file}",
    onlyif  => [
      "/usr/bin/test -f ${pam_config_file}",
      "/bin/grep -qv 'pam_oidc.so' ${pam_config_file}",
    ],
    require => Class['unix_oidc::install'],
  }
}
