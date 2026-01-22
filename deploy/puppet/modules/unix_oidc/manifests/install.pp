# @summary Install unix-oidc and dependencies
#
# This class handles the installation of unix-oidc and its dependencies.
# It ensures required packages are present and downloads/runs the installer.
#
# @api private
#
class unix_oidc::install {
  assert_private()

  # Ensure required packages are installed
  $required_packages = ['curl', 'jq']

  package { $required_packages:
    ensure => present,
  }

  # Determine installer URL based on version
  $base_url = 'https://github.com/unix-oidc/unix-oidc/releases'
  $installer_url = $unix_oidc::version ? {
    'latest' => "${base_url}/latest/download/install.sh",
    default  => "${base_url}/download/v${unix_oidc::version}/install.sh",
  }

  # Create installation directory
  file { '/opt/unix-oidc':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # Download and execute installer
  # The installer is idempotent and will skip if already installed
  exec { 'download-unix-oidc-installer':
    command => "/usr/bin/curl -fsSL ${installer_url} -o /opt/unix-oidc/install.sh",
    creates => '/opt/unix-oidc/install.sh',
    require => [
      Package['curl'],
      File['/opt/unix-oidc'],
    ],
  }

  file { '/opt/unix-oidc/install.sh':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    require => Exec['download-unix-oidc-installer'],
  }

  # Build installer arguments
  $version_arg = $unix_oidc::version ? {
    'latest' => '',
    default  => "--version ${unix_oidc::version}",
  }

  $agent_arg = $unix_oidc::install_agent ? {
    true    => '--with-agent',
    default => '',
  }

  $install_args = strip("${version_arg} ${agent_arg}")

  exec { 'run-unix-oidc-installer':
    command     => "/opt/unix-oidc/install.sh ${install_args}",
    creates     => '/usr/lib/security/pam_oidc.so',
    environment => ['DEBIAN_FRONTEND=noninteractive'],
    require     => File['/opt/unix-oidc/install.sh'],
    timeout     => 300,
  }
}
