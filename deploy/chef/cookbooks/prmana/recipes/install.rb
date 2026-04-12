#
# Cookbook:: prmana
# Recipe:: install
#
# Installs the prmana PAM module and optional agent
#

# Ensure required packages are installed
package %w[curl jq] do
  action :install
end

# Create installation directory
directory node['prmana']['install_dir'] do
  owner 'root'
  group 'root'
  mode '0755'
  recursive true
  action :create
end

# Create configuration directory
directory node['prmana']['config_dir'] do
  owner 'root'
  group 'root'
  mode '0755'
  recursive true
  action :create
end

# Create cache directory
directory node['prmana']['cache_dir'] do
  owner 'root'
  group 'root'
  mode '0750'
  recursive true
  action :create
end

# Download the installer script
installer_path = "#{Chef::Config[:file_cache_path]}/prmana-install.sh"

remote_file installer_path do
  source 'https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh'
  owner 'root'
  group 'root'
  mode '0755'
  action :create
  notifies :run, 'execute[run_prmana_installer]', :immediately
end

# Build installer arguments
installer_args = []
installer_args << "--version #{node['prmana']['version']}" unless node['prmana']['version'] == 'latest'
installer_args << '--with-agent' if node['prmana']['install_agent']
installer_args << '--no-agent' unless node['prmana']['install_agent']

# Run the installer
execute 'run_prmana_installer' do
  command "#{installer_path} #{installer_args.join(' ')}"
  environment(
    'PRMANA_NONINTERACTIVE' => '1'
  )
  action :nothing
  not_if { ::File.exist?('/usr/lib/security/pam_prmana.so') || ::File.exist?('/lib/security/pam_prmana.so') }
end

# Create marker file to track installed version
file "#{node['prmana']['install_dir']}/.installed_version" do
  content node['prmana']['version']
  owner 'root'
  group 'root'
  mode '0644'
  action :create
end
