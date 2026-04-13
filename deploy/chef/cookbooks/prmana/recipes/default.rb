#
# Cookbook:: prmana
# Recipe:: default
#
# Installs and configures prmana PAM module
#

include_recipe 'prmana::install'
include_recipe 'prmana::configure'
