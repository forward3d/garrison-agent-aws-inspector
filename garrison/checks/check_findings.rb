module Garrison
  module Checks
    class CheckFindings < Check

      def settings
        self.source ||= 'aws-inspector'
        self.family ||= 'software'
        self.type ||= 'security'
        self.options[:regions] ||= 'all'
        self.options[:rules_packages] ||= 'all'
        self.options[:severity_threshold] ||= %w(undefined informational low medium high)
        self.options[:excluded_cis_rules] ||= []
      end

      def key_values
        [
          { key: 'datacenter',  value: 'aws' },
          { key: 'aws-service', value: 'inspector' }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'
        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          inspector = Aws::Inspector::Client.new(region: region)

          # we have to pull this everytime, as each region has different rules packages
          rules_packages = AwsHelper.list_rules_packages(inspector, options[:rules_packages])

          # retrieve all runs based on rules packages, as the API doesn't do any ordering
          # then group them by template ARN, keep only the latest run for each template ARN
          assessment_runs = AwsHelper.list_assessment_runs(inspector, rules_packages)
          grouped_sorted_runs = assessment_runs.sort_by(&:completed_at).reverse.group_by(&:assessment_template_arn)
          latest_runs = grouped_sorted_runs.map { |r, a| a.first.arn }

          findings = AwsHelper.list_findings(inspector, latest_runs, rules_packages, options[:severity_threshold])
          findings.each do |finding|

            # are we dealing with CIS findings?
            if finding.attributes.find { |a| a.key == "CIS_BENCHMARK_PROFILE" }
              benchmark = finding.attributes.find { |a| a.key == "BENCHMARK_ID" }
              rule = finding.attributes.find { |a| a.key == "BENCHMARK_RULE_ID" }

              # lookup which excluded rules might apply to this benchmark
              excluded_rules = lookup_exclusions(benchmark.value)

              matches = /^([.0-9]*?)\s/.match(rule.value)
              if matches && excluded_rules.include?(matches[1])
                Logging.info "Skipping excluded finding (rule_id=#{matches[1]} arn=#{finding.arn})"
                next
              end
            end

            alert(
              name: rules_packages.find { |rp| rp.arn == finding.service_attributes.rules_package_arn }.name,
              target: finding.asset_attributes.agent_id,
              detail: finding.title,
              no_repeat: false,
              finding: finding.to_h.to_json,
              finding_id: "#{finding.asset_attributes.agent_id}/#{finding.id}",
              first_detected_at: finding.created_at,
              last_detected_at: finding.created_at,
              external_severity: aws_severity_to_garrison_severity(finding.severity),
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/inspector/home?region=#{region}#/finding?filter=#{URI.escape({ "findingArns" => finding.arn }.to_json)}"
                }
              ],
              key_values: [
                {
                  key: 'aws-account',
                  value: AwsHelper.whoami.account
                },
                {
                  key: 'aws-region',
                  value: region
                }
              ]
            )

          end
        end
      end

      private

      def lookup_exclusions(benchmark_id)
        if benchmark_id.include?("CIS Amazon Linux Benchmark")
          @options[:excluded_cis_rules][:amazon_linux]
        elsif benchmark_id.include?("CIS Amazon Linux 2 Benchmark")
          @options[:excluded_cis_rules][:amazon_linux_2]
        elsif benchmark_id.include?("CentOS Linux 6 Benchmark")
          @options[:excluded_cis_rules][:centos_6]
        elsif benchmark_id.include?("CentOS Linux 7 Benchmark")
          @options[:excluded_cis_rules][:centos_7]
        elsif benchmark_id.include?("Ubuntu Linux 14.04 LTS Benchmark")
          @options[:excluded_cis_rules][:ubuntu_trusty]
        elsif benchmark_id.include?("Ubuntu Linux 15.04 LTS Benchmark")
          @options[:excluded_cis_rules][:ubuntu_xenial]
        end
      end

      def aws_severity_to_garrison_severity(severity)
        case severity.downcase
        when 'high'
          'high'
        when 'medium'
          'medium'
        when 'low'
          'low'
        when 'informational'
          'info'
        when 'undefined'
          'info'
        else
          'info'
        end
      end

    end
  end
end
