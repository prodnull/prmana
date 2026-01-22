#
# Cookbook:: unix_oidc
# Recipe:: configure
#
# Configures the unix-oidc PAM module
#

# Validate required attributes
raise 'unix_oidc: issuer attribute is required' if node['unix_oidc']['issuer'].nil?

# Create configuration directory if not exists
directory node['unix_oidc']['config_dir'] do
  owner 'root'
  group 'root'
  mode '0755'
  recursive true
  action :create
end

# Deploy configuration file from template
template "#{node['unix_oidc']['config_dir']}/config.env" do
  source 'config.env.erb'
  owner 'root'
  group 'root'
  mode '0640'
  variables(
    issuer: node['unix_oidc']['issuer'],
    client_id: node['unix_oidc']['client_id'],
    enable_dpop: node['unix_oidc']['enable_dpop'],
    log_level: node['unix_oidc']['log_level'],
    cache_dir: node['unix_oidc']['cache_dir'],
    claim_mappings: node['unix_oidc']['claim_mappings'],
    allowed_groups: node['unix_oidc']['allowed_groups']
  )
  action :create
end

# Configure PAM services if specified
node['unix_oidc']['pam_services'].each do |service|
  pam_config_path = "/etc/pam.d/#{service}"

  # Only modify if PAM config exists
  next unless ::File.exist?(pam_config_path)

  pam_oidc_line = 'auth sufficient pam_oidc.so'

  # Check if already configured
  ruby_block "configure_pam_#{service}" do
    block do
      pam_content = ::File.read(pam_config_path)

      unless pam_content.include?('pam_oidc.so')
        # Find the first auth line and insert before it
        lines = pam_content.lines
        insert_index = lines.find_index { |line| line =~ /^auth\s+/ }

        if insert_index
          lines.insert(insert_index, "#{pam_oidc_line}\n")
          ::File.write(pam_config_path, lines.join)
          Chef::Log.info("Configured PAM service: #{service}")
        else
          Chef::Log.warn("Could not find auth section in #{pam_config_path}")
        end
      end
    end
    action :run
    not_if { ::File.read(pam_config_path).include?('pam_oidc.so') }
  end
end

# Create systemd service for oidc-agent if installed
if node['unix_oidc']['install_agent']
  systemd_unit 'oidc-agent.service' do
    content(
      Unit: {
        Description: 'OIDC Agent for unix-oidc',
        After: 'network-online.target',
        Wants: 'network-online.target'
      },
      Service: {
        Type: 'simple',
        ExecStart: '/usr/local/bin/oidc-agent --foreground',
        Restart: 'on-failure',
        RestartSec: '5s',
        User: 'root',
        EnvironmentFile: "#{node['unix_oidc']['config_dir']}/config.env"
      },
      Install: {
        WantedBy: 'multi-user.target'
      }
    )
    action [:create, :enable]
    only_if { ::File.exist?('/usr/local/bin/oidc-agent') }
  end
end
