#
# Cookbook:: unix_oidc
# Recipe:: install
#
# Installs the unix-oidc PAM module and optional agent
#

# Ensure required packages are installed
package %w[curl jq] do
  action :install
end

# Create installation directory
directory node['unix_oidc']['install_dir'] do
  owner 'root'
  group 'root'
  mode '0755'
  recursive true
  action :create
end

# Create configuration directory
directory node['unix_oidc']['config_dir'] do
  owner 'root'
  group 'root'
  mode '0755'
  recursive true
  action :create
end

# Create cache directory
directory node['unix_oidc']['cache_dir'] do
  owner 'root'
  group 'root'
  mode '0750'
  recursive true
  action :create
end

# Download the installer script
installer_path = "#{Chef::Config[:file_cache_path]}/unix-oidc-install.sh"

remote_file installer_path do
  source 'https://raw.githubusercontent.com/unix-oidc/unix-oidc/main/install.sh'
  owner 'root'
  group 'root'
  mode '0755'
  action :create
  notifies :run, 'execute[run_unix_oidc_installer]', :immediately
end

# Build installer arguments
installer_args = []
installer_args << "--version #{node['unix_oidc']['version']}" unless node['unix_oidc']['version'] == 'latest'
installer_args << '--with-agent' if node['unix_oidc']['install_agent']
installer_args << '--no-agent' unless node['unix_oidc']['install_agent']

# Run the installer
execute 'run_unix_oidc_installer' do
  command "#{installer_path} #{installer_args.join(' ')}"
  environment(
    'UNIX_OIDC_NONINTERACTIVE' => '1'
  )
  action :nothing
  not_if { ::File.exist?('/usr/lib/security/pam_oidc.so') || ::File.exist?('/lib/security/pam_oidc.so') }
end

# Create marker file to track installed version
file "#{node['unix_oidc']['install_dir']}/.installed_version" do
  content node['unix_oidc']['version']
  owner 'root'
  group 'root'
  mode '0644'
  action :create
end
