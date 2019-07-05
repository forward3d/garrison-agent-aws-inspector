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
    @options[:excluded_cis_rules] = ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS'] ? ENV['GARRISON_AWS_INSPECTOR_EXCLUDED_CIS'].split(',') : nil
  end
end
