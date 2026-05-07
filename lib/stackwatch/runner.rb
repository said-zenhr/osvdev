module StackWatch
  class Runner
    def self.call(config, stdout: $stdout, stderr: $stderr, source: nil, notifier: nil)
      new(config, stdout: stdout, stderr: stderr, source: source, notifier: notifier).run
    end

    def initialize(config, stdout:, stderr:, source: nil, notifier: nil)
      @config   = config
      @stdout   = stdout
      @stderr   = stderr
      @state    = State.load(config.state_path)
      @source   = source || Sources::OSV.new(config.packages)
      @notifier = notifier || (config.slack_webhook_url ? Notifiers::Slack.new(config.slack_webhook_url) : nil)
    end

    def run
      results   = @source.fetch_all
      total_new = 0
      errors    = []

      results.each do |package, vulns|
        new_vulns = @state.diff(package, vulns)
        next if new_vulns.empty?

        new_vulns.each do |vuln|
          begin
            @notifier&.notify(package: package, vuln: vuln)
          rescue Notifiers::SlackError => e
            errors << e
            @stderr.puts "WARN: Slack failed for #{vuln.id}: #{e.message}"
          end
          @stdout.puts "  [#{package.tier.upcase}] #{vuln.id} — #{package.ecosystem}/#{package.name}"
        end

        @state.mark_seen(package, new_vulns)
        total_new += new_vulns.size
      end

      @state.persist
      @notifier&.post_summary(total_new) rescue nil
      @stdout.puts "StackWatch: #{total_new} new vulnerabilit#{total_new == 1 ? "y" : "ies"} found."
      raise errors.first if errors.any?
      total_new
    end
  end
end
