require "json"
require "net/http"
require "psych"
require "set"
require "time"

module StackWatch
  VERSION = "0.1.0"

  class ConfigError < StandardError; end

  module Sources
    class OSVError < StandardError; end
  end

  module Notifiers
    class SlackError < StandardError; end
  end

  autoload :Config,  "stackwatch/config"
  autoload :State,   "stackwatch/state"
  autoload :Vuln,    'stackwatch/vuln'
  autoload :Runner,  "stackwatch/runner"
  autoload :CLI,     "stackwatch/cli"

  module Sources
    autoload :OSV, "stackwatch/sources/osv"
  end

  module Notifiers
    autoload :Slack, "stackwatch/notifiers/slack"
  end
end
