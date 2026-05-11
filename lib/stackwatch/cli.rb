require 'thor'

module StackWatch
  class CLI < Thor
    def self.exit_on_failure?
      true
    end
    STARTER_TEMPLATE = <<~YAML
      # StackWatch configuration
      # Docs: https://github.com/yourorg/stackwatch

      state_path: ./state.json

      notifications:
        slack:
          webhook_url: "${STACKWATCH_SLACK_WEBHOOK}"

      filters:
        max_age_days: 30   # set to false to report full historical backlog

      packages:
        - name: rails
          ecosystem: RubyGems
          tier: critical
        - name: django
          ecosystem: PyPI
          tier: standard
        - name: next
          ecosystem: npm
          tier: standard
    YAML

    desc 'run', 'Query CVEs for your stack and post new ones to Slack'
    option :config,     aliases: '-c', default: 'stack.yml', desc: 'Path to stack.yml'
    option :state_path, aliases: '-s', default: nil,         desc: 'Override state.json path'
    map ['run'] => :scan

    def scan
      config = Config.load(
        path: options[:config],
        state_path_override: options[:state_path]
      )
      Runner.call(config)
    rescue ConfigError, Sources::OSVError => e
      warn "ERROR: #{e.message}"
      exit 1
    rescue Notifiers::SlackError => e
      warn "ERROR (Slack): #{e.message}"
      exit 1
    end

    desc 'init', 'Generate a starter stack.yml in the current directory'
    option :force, aliases: '-f', type: :boolean, default: false, desc: 'Overwrite existing file'
    def init
      target = 'stack.yml'
      if File.exist?(target) && !options[:force]
        warn "#{target} already exists. Use --force to overwrite."
        exit 1
      end
      File.write(target, STARTER_TEMPLATE)
      puts "Created #{target} — edit it to list your packages, then set STACKWATCH_SLACK_WEBHOOK."
    end
  end
end
