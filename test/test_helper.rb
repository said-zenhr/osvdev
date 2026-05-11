$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

require 'minitest/autorun'
require 'minitest/reporters'
require 'webmock/minitest'
require 'stackwatch'
require 'stackwatch/config'
require 'stackwatch/vuln'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

WebMock.disable_net_connect!

def fixture(name)
  File.read(File.expand_path("fixtures/#{name}", __dir__))
end

def fixture_path(name)
  File.expand_path("fixtures/#{name}", __dir__)
end

def stub_vuln(id: 'CVE-STUB', summary: '', cvss_score: 'N/A', affected: 'unknown',
              fixed: nil, url: nil, published: nil, withdrawn: nil)
  StackWatch::Vuln.new(
    id: id, summary: summary, cvss_score: cvss_score,
    affected: affected, fixed: fixed,
    url: url || "https://osv.dev/vulnerability/#{id}",
    published: published, withdrawn: withdrawn
  )
end
