# @summary Install prmana and dependencies
#
# This class handles the installation of prmana and its dependencies.
# It ensures required packages are present and downloads/runs the installer.
#
# @api private
#
class prmana::install {
  assert_private()

  # Ensure required packages are installed
  $required_packages = ['curl', 'jq']

  package { $required_packages:
    ensure => present,
  }

  # Determine installer URL based on version
  $base_url = 'https://github.com/prodnull/prmana/releases'
  $installer_url = $prmana::version ? {
    'latest' => "${base_url}/latest/download/install.sh",
    default  => "${base_url}/download/v${prmana::version}/install.sh",
  }

  # Create installation directory
  file { '/opt/prmana':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # Download and execute installer
  exec { 'download-prmana-installer':
    command => "/usr/bin/curl -fsSL ${installer_url} -o /opt/prmana/install.sh",
    creates => '/opt/prmana/install.sh',
    require => [
      Package['curl'],
      File['/opt/prmana'],
    ],
  }

  file { '/opt/prmana/install.sh':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    require => Exec['download-prmana-installer'],
  }

  # Build installer arguments
  $version_arg = $prmana::version ? {
    'latest' => '',
    default  => "--version ${prmana::version}",
  }

  $agent_arg = $prmana::install_agent ? {
    true    => '--with-agent',
    default => '',
  }

  $install_args = strip("${version_arg} ${agent_arg}")

  exec { 'run-prmana-installer':
    command     => "/opt/prmana/install.sh ${install_args}",
    creates     => '/usr/lib/security/pam_prmana.so',
    environment => ['DEBIAN_FRONTEND=noninteractive'],
    require     => File['/opt/prmana/install.sh'],
    timeout     => 300,
  }
}
