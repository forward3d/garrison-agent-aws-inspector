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

          rescue NoMethodError => e
            binding.pry
            raise e
          end
        end
      end

      private

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
