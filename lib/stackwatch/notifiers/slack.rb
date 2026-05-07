module StackWatch
  module Notifiers
    class Slack
      TIMEOUT_SEC = 10

      def initialize(webhook_url)
        @uri = URI(webhook_url)
      end

      def notify(package:, vuln:)
        post(build_payload(package: package, vuln: vuln))
      end

      def post_summary(total_new)
        emoji = total_new.zero? ? ":white_check_mark:" : ":rotating_light:"
        post({ "text" => "#{emoji} StackWatch: #{total_new} new vulnerabilit#{total_new == 1 ? "y" : "ies"} found." })
      end

      private

      def build_payload(package:, vuln:)
        { "text" => format_message(package: package, vuln: vuln) }
      end

      def format_message(package:, vuln:)
        mention   = package.critical? ? "<!here> " : ""
        fixed_str = vuln.fixed || "no patch"

        [
          "#{mention}:rotating_light: New CVE for *#{package.name}* (#{package.ecosystem})",
          "*#{vuln.id}* — CVSS #{vuln.cvss_score}",
          vuln.summary,
          "Affected: #{vuln.affected}   Patched: #{fixed_str}",
          "<#{vuln.url}|View on osv.dev>"
        ].join("\n")
      end

      def post(payload)
        http = Net::HTTP.new(@uri.host, @uri.port)
        http.use_ssl      = (@uri.scheme == "https")
        http.open_timeout = TIMEOUT_SEC
        http.read_timeout = TIMEOUT_SEC

        req = Net::HTTP::Post.new(@uri.request_uri)
        req["Content-Type"] = "application/json"
        req.body = JSON.generate(payload)

        res = http.request(req)
        raise SlackError, "Slack webhook error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)

        true
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise SlackError, "Slack webhook timeout: #{e.message}"
      end
    end

  end
end
