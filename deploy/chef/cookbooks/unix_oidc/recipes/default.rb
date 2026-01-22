#
# Cookbook:: unix_oidc
# Recipe:: default
#
# Installs and configures unix-oidc PAM module
#

include_recipe 'unix_oidc::install'
include_recipe 'unix_oidc::configure'
