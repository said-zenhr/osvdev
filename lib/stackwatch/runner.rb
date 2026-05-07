module StackWatch
  class Runner
    def self.call(config, stdout: $stdout, stderr: $stderr)
      new(config, stdout: stdout, stderr: stderr).run
    end

    def initialize(config, stdout:, stderr:)
      @config = config
      @stdout = stdout
      @stderr = stderr
      @state  = State.load(config.state_path)
      @slack  = config.slack_webhook_url ? Notifiers::Slack.new(config.slack_webhook_url) : nil
    end

    def run
      results   = Sources::OSV.new(@config.packages).fetch_all
      total_new = 0

      results.each do |package, vulns|
        new_vulns = @state.diff(package, vulns)
        next if new_vulns.empty?

        new_vulns.each do |vuln|
          @slack&.notify(package: package, vuln: vuln)
          @stdout.puts "  [#{package.tier.upcase}] #{vuln["id"]} — #{package.ecosystem}/#{package.name}"
        end

        @state.mark_seen(package, new_vulns)
        total_new += new_vulns.size
      end

      @state.persist
      @slack&.post_summary(total_new)
      @stdout.puts "StackWatch: #{total_new} new vulnerabilit#{total_new == 1 ? "y" : "ies"} found."
      total_new
    rescue Sources::OSVError => e
      @stderr.puts "ERROR (OSV): #{e.message}"
      exit 1
    rescue Notifiers::SlackError => e
      @stderr.puts "ERROR (Slack): #{e.message}"
      # Do not persist — let next run retry the failed notification
      exit 1
    end
  end
end
