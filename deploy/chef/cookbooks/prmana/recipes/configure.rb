#
# Cookbook:: prmana
# Recipe:: configure
#
# Configures the prmana PAM module
#

# Validate required attributes
raise 'prmana: issuer attribute is required' if node['prmana']['issuer'].nil?

# Create configuration directory if not exists
directory node['prmana']['config_dir'] do
  owner 'root'
  group 'root'
  mode '0755'
  recursive true
  action :create
end

# Deploy configuration file from template
template "#{node['prmana']['config_dir']}/config.env" do
  source 'config.env.erb'
  owner 'root'
  group 'root'
  mode '0640'
  variables(
    issuer: node['prmana']['issuer'],
    client_id: node['prmana']['client_id'],
    enable_dpop: node['prmana']['enable_dpop'],
    log_level: node['prmana']['log_level'],
    cache_dir: node['prmana']['cache_dir'],
    claim_mappings: node['prmana']['claim_mappings'],
    allowed_groups: node['prmana']['allowed_groups']
  )
  action :create
end

# Configure PAM services if specified
node['prmana']['pam_services'].each do |service|
  pam_config_path = "/etc/pam.d/#{service}"

  # Only modify if PAM config exists
  next unless ::File.exist?(pam_config_path)

  pam_line = 'auth sufficient pam_prmana.so'

  # Check if already configured
  ruby_block "configure_pam_#{service}" do
    block do
      pam_content = ::File.read(pam_config_path)

      unless pam_content.include?('pam_prmana.so')
        # Find the first auth line and insert before it
        lines = pam_content.lines
        insert_index = lines.find_index { |line| line =~ /^auth\s+/ }

        if insert_index
          lines.insert(insert_index, "#{pam_line}\n")
          ::File.write(pam_config_path, lines.join)
          Chef::Log.info("Configured PAM service: #{service}")
        else
          Chef::Log.warn("Could not find auth section in #{pam_config_path}")
        end
      end
    end
    action :run
    not_if { ::File.read(pam_config_path).include?('pam_prmana.so') }
  end
end

# Create systemd service for prmana-agent if installed
if node['prmana']['install_agent']
  systemd_unit 'prmana-agent.service' do
    content(
      Unit: {
        Description: 'prmana Agent',
        After: 'network-online.target',
        Wants: 'network-online.target'
      },
      Service: {
        Type: 'simple',
        ExecStart: '/usr/local/bin/prmana-agent --foreground',
        Restart: 'on-failure',
        RestartSec: '5s',
        User: 'root',
        EnvironmentFile: "#{node['prmana']['config_dir']}/config.env"
      },
      Install: {
        WantedBy: 'multi-user.target'
      }
    )
    action [:create, :enable]
    only_if { ::File.exist?('/usr/local/bin/prmana-agent') }
  end
end
