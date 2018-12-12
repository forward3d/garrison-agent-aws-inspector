module Garrison
  class AwsHelper

    class << self
      def whoami
        @whoami ||= Aws::STS::Client.new(region: 'us-east-1').get_caller_identity
      end

      def all_regions
        Aws::Partitions.partition('aws').service('Inspector').regions
      end

      def list_rules_packages(inspector, filter)
        rules = []
        next_token = nil

        loop do
          Logging.debug "AWS SDK - Listing Rules Packages (next_token=#{next_token})"
          results = inspector.list_rules_packages(next_token: next_token)

          Logging.debug "AWS SDK - Realizing Rules Packages (count=#{results.rules_package_arns.count})"
          rules_packages = inspector.describe_rules_packages(rules_package_arns: results.rules_package_arns)
          rules_packages.rules_packages.map do |item|
            if filter == 'all'
              rules << item
            else
              rules << item if filter.include?(item.name)
            end
          end

          if results.next_token != nil
            next_token = results.next_token
          else
            raise StopIteration
          end
        end

        rules
      end

      def list_assessment_runs(inspector, filter)
        Enumerator.new do |yielder|
          next_token = nil

          loop do
            Logging.debug "AWS SDK - Listing Assessment Runs (next_token=#{next_token})"
            results = inspector.list_assessment_runs({
              filter: {
                states: ["COMPLETED"],
                rules_package_arns: filter.map(&:arn),
              },
              next_token: next_token,
            })

            raise StopIteration if results.assessment_run_arns.count == 0

            Logging.debug "AWS SDK - Realizing Assessment Runs (count=#{results.assessment_run_arns.count})"
            assessment_runs = inspector.describe_assessment_runs(assessment_run_arns: results.assessment_run_arns)
            assessment_runs.assessment_runs.map { |item| yielder << item }

            if results.next_token != nil
              next_token = results.next_token
            else
              raise StopIteration
            end
          end
        end.lazy
      end

      def list_findings(inspector, filter, rules_packages, severities)
        Enumerator.new do |yielder|
          next_token = nil

          loop do
            Logging.debug "AWS SDK - Listing Findings (next_token=#{next_token})"
            results = inspector.list_findings({
              assessment_run_arns: filter,
              filter: { severities: severities.map(&:capitalize) },
              next_token: next_token,
              max_results: 50,
            })

            raise StopIteration if results.finding_arns.count == 0

            Logging.debug "AWS SDK - Realizing Findings (count=#{results.finding_arns.count})"
            findings = inspector.describe_findings(finding_arns: results.finding_arns)
            findings.findings.map do |item|
              yielder << item if rules_packages.find { |rp| rp.arn == item.service_attributes.rules_package_arn }
            end

            if results.next_token != nil
              next_token = results.next_token
            else
              raise StopIteration
            end
          end
        end.lazy
      end

    end
  end
end
