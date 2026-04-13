# @summary Configure prmana
#
# This class manages the configuration of prmana including the
# environment configuration file and PAM service integration.
#
# @api private
#
class prmana::config {
  assert_private()

  # Ensure configuration directory exists
  file { '/etc/prmana':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # Generate configuration file from template
  file { '/etc/prmana/config.env':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp('prmana/config.env.epp', {
      'issuer'      => $prmana::issuer,
      'client_id'   => $prmana::client_id,
      'enable_dpop' => $prmana::enable_dpop,
    }),
    require => File['/etc/prmana'],
  }

  # Configure PAM services if specified
  if !empty($prmana::pam_services) {
    $prmana::pam_services.each |String $service| {
      prmana::config::pam_service { $service: }
    }
  }
}

# @summary Configure a PAM service for prmana
#
# @param service_name
#   The name of the PAM service to configure.
#
define prmana::config::pam_service (
  String $service_name = $title,
) {
  $pam_config_file = "/etc/pam.d/${service_name}"
  $pam_line = 'auth sufficient pam_prmana.so'

  # Only add the PAM line if the service file exists and doesn't already have it
  exec { "configure-pam-${service_name}":
    command => "/bin/sed -i '1a ${pam_line}' ${pam_config_file}",
    onlyif  => [
      "/usr/bin/test -f ${pam_config_file}",
      "/bin/grep -qv 'pam_prmana.so' ${pam_config_file}",
    ],
    require => Class['prmana::install'],
  }
}
