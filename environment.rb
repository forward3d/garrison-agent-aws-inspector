require 'bundler'
Bundler.require(:default)
ROOT = File.dirname(__FILE__)

Dir[File.join(ROOT, 'garrison/lib/*.rb')].each do |file|
  require file
end

Dir[File.join(ROOT, 'garrison/checks/*.rb')].each do |file|
  require file
end

Garrison::Api.configure do |config|
  config.url  = ENV['GARRISON_URL']
  config.uuid = ENV['GARRISON_AGENT_UUID']
end

Garrison::Logging.info('Garrison Agent - AWS Inspector')

module Garrison
  module Checks
    @options = {}
    @options[:regions] = ENV['GARRISON_AWS_REGIONS'] ? ENV['GARRISON_AWS_REGIONS'].split(',') : nil
    @options[:rules_packages] = ENV['GARRISON_AWS_INSPECTOR_RULES_PACKAGE_NAMES'] ? ENV['GARRISON_AWS_INSPECTOR_RULES_PACKAGE_NAMES'].split(',') : nil
    @options[:severity_threshold] = ENV['GARRISON_AWS_INSPECTOR_THRESHOLD'] ? ENV['GARRISON_AWS_INSPECTOR_THRESHOLD'].split(',') : nil
    @options[:excluded_cis_rules] = {}
    @options[:excluded_cis_rules][:amazon_linux] = ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_AMAZON_LINUX'] ? ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_AMAZON_LINUX'].split(',') : []
    @options[:excluded_cis_rules][:amazon_linux_2] = ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_AMAZON_LINUX_2'] ? ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_AMAZON_LINUX_2'].split(',') : []
    @options[:excluded_cis_rules][:centos_6] = ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_CENTOS_6'] ? ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_CENTOS_6'].split(',') : []
    @options[:excluded_cis_rules][:centos_7] = ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_CENTOS_7'] ? ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_CENTOS_7'].split(',') : []
    @options[:excluded_cis_rules][:ubuntu_trusty] = ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_UBUNTU_TRUSTY'] ? ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_UBUNTU_TRUSTY'].split(',') : []
    @options[:excluded_cis_rules][:ubuntu_xenial] = ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_UBUNTU_XENIAL'] ? ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS_UBUNTU_XENIAL'].split(',') : []
  end
end
