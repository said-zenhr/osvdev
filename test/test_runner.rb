require_relative "test_helper"
require "tmpdir"
require "fileutils"
require "stringio"

class TestRunner < Minitest::Test
  OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
  WEBHOOK_URL   = "https://hooks.slack.com/services/test"

  # Raw OSV API format (not normalized)
  RAW_VULN = {
    "id"       => "CVE-2024-99999",
    "summary"  => "Test vuln",
    "severity" => [{ "type" => "CVSS_V3", "score" => "8.0" }],
    "affected" => [
      { "ranges" => [{ "events" => [{ "introduced" => "1.0" }, { "fixed" => "2.0" }] }] }
    ]
  }.freeze

  def setup
    WebMock.reset!
    @tmpdir     = Dir.mktmpdir
    @state_path = File.join(@tmpdir, "state.json")

    @pkg = StackWatch::Package.new(name: "django", ecosystem: "PyPI", tier: "critical")

    @config = StackWatch::AppConfig.new(
      packages:          [@pkg],
      slack_webhook_url: WEBHOOK_URL,
      state_path:        @state_path
    )
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  def stub_osv(vulns: [RAW_VULN])
    body = JSON.generate(results: [{ vulns: vulns }])
    stub_request(:post, OSV_BATCH_URL)
      .to_return(status: 200, body: body, headers: { "Content-Type" => "application/json" })
  end

  def stub_slack(status: 200)
    stub_request(:post, WEBHOOK_URL).to_return(status: status, body: "ok")
  end

  def run_runner
    out = StringIO.new
    err = StringIO.new
    count = StackWatch::Runner.call(@config, stdout: out, stderr: err)
    [count, out.string, err.string]
  end

  def test_notifies_new_vulns
    stub_osv
    stub_slack
    count, out, = run_runner

    assert_equal 1, count
    assert_match "CVE-2024-99999", out
    assert_requested(:post, WEBHOOK_URL, times: 2)
  end

  def test_skips_already_seen_vulns
    # Pre-populate state with the vuln
    state = StackWatch::State.load(@state_path)
    state.mark_seen(@pkg, [stub_vuln(id: "CVE-2024-99999")])
    state.persist

    stub_osv
    stub_slack
    count, = run_runner

    assert_equal 0, count
    assert_requested(:post, WEBHOOK_URL, times: 1)
  end

  def test_persists_state_on_success
    stub_osv
    stub_slack
    run_runner

    assert File.exist?(@state_path)
    data = JSON.parse(File.read(@state_path))
    assert_includes data.dig("packages", "PyPI/django"), "CVE-2024-99999"
  end

  def test_does_not_persist_on_slack_failure
    stub_osv
    stub_request(:post, WEBHOOK_URL).to_return(status: 500, body: "error")

    assert_raises(StackWatch::Notifiers::SlackError) do
      StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: StringIO.new)
    end

    refute File.exist?(@state_path)
  end

  def test_raises_on_osv_failure
    stub_request(:post, OSV_BATCH_URL).to_return(status: 503, body: "unavailable")

    assert_raises(StackWatch::Sources::OSVError) do
      StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: StringIO.new)
    end
  end
end
