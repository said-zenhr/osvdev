require_relative 'test_helper'
require 'tmpdir'
require 'fileutils'
require 'stringio'

class FakeSource
  def initialize(results)
    @results = results
  end

  def fetch_all
    @results
  end
end

class FakeNotifier
  attr_reader :notifications, :summaries

  def initialize
    @notifications = []
    @summaries = []
  end

  def notify(package:, vuln:)
    @notifications << { package: package, vuln: vuln }
  end

  def post_summary(total_new)
    @summaries << total_new
  end
end

class FailingNotifier
  def notify(package:, vuln:)
    raise StackWatch::Notifiers::SlackError, 'webhook failed'
  end

  def post_summary(_total_new)
    raise StackWatch::Notifiers::SlackError, 'webhook failed'
  end
end

class TestRunner < Minitest::Test
  def setup
    @tmpdir     = Dir.mktmpdir
    @state_path = File.join(@tmpdir, 'state.json')
    @pkg        = StackWatch::Package.new(name: 'django', ecosystem: 'PyPI', tier: 'critical')
    @vuln       = stub_vuln(id: 'CVE-2024-99999', summary: 'Test vuln', cvss_score: '8.0',
                            affected: '>=1.0', fixed: '2.0')
    @config     = StackWatch::AppConfig.new(
      packages: [@pkg],
      slack_webhook_url: nil,
      state_path: @state_path,
      max_age_days: nil
    )
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  def test_notifies_new_vulns
    source   = FakeSource.new({ @pkg => [@vuln] })
    notifier = FakeNotifier.new

    out   = StringIO.new
    count = StackWatch::Runner.call(@config, stdout: out, stderr: StringIO.new,
                                             source: source, notifier: notifier)

    assert_equal 1, count
    assert_match 'CVE-2024-99999', out.string
    assert_equal 1, notifier.notifications.size
    assert_equal 'CVE-2024-99999', notifier.notifications[0][:vuln].id
    assert_equal [1], notifier.summaries
  end

  def test_skips_already_seen_vulns
    state = StackWatch::State.load(@state_path)
    state.mark_seen(@pkg, [stub_vuln(id: 'CVE-2024-99999')])
    state.persist

    source   = FakeSource.new({ @pkg => [@vuln] })
    notifier = FakeNotifier.new

    count = StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: StringIO.new,
                                             source: source, notifier: notifier)

    assert_equal 0, count
    assert_empty notifier.notifications
    assert_equal [0], notifier.summaries
  end

  def test_persists_state_on_success
    source = FakeSource.new({ @pkg => [@vuln] })

    StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: StringIO.new, source: source)

    assert File.exist?(@state_path)
    data = JSON.parse(File.read(@state_path))
    assert_includes data.dig('packages', 'PyPI/django'), 'CVE-2024-99999'
  end

  def test_persists_state_despite_notifier_failure
    source   = FakeSource.new({ @pkg => [@vuln] })
    notifier = FailingNotifier.new

    assert_raises(StackWatch::Notifiers::SlackError) do
      StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: StringIO.new,
                                       source: source, notifier: notifier)
    end

    assert File.exist?(@state_path), 'State must be persisted even when Slack fails'
    data = JSON.parse(File.read(@state_path))
    assert_includes data.dig('packages', 'PyPI/django'), 'CVE-2024-99999'
  end

  def test_partial_slack_failure_persists_all_seen
    pkg2  = StackWatch::Package.new(name: 'next', ecosystem: 'npm', tier: 'standard')
    vuln2 = stub_vuln(id: 'CVE-2024-88888', summary: 'Another vuln')

    call_count = 0
    notifier = FakeNotifier.new
    notifier.define_singleton_method(:notify) do |package:, vuln:|
      call_count += 1
      raise StackWatch::Notifiers::SlackError, 'boom' if call_count == 1

      @notifications << { package: package, vuln: vuln }
    end

    source = FakeSource.new({ @pkg => [@vuln], pkg2 => [vuln2] })
    stderr = StringIO.new

    assert_raises(StackWatch::Notifiers::SlackError) do
      StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: stderr,
                                       source: source, notifier: notifier)
    end

    assert File.exist?(@state_path)
    data = JSON.parse(File.read(@state_path))
    assert_includes data.dig('packages', 'PyPI/django'), 'CVE-2024-99999'
    assert_includes data.dig('packages', 'npm/next'), 'CVE-2024-88888'
    assert_match 'WARN', stderr.string
  end

  def test_raises_on_source_failure
    source = FakeSource.new(nil)
    source.define_singleton_method(:fetch_all) { raise StackWatch::Sources::OSVError, 'API down' }

    assert_raises(StackWatch::Sources::OSVError) do
      StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: StringIO.new, source: source)
    end
  end

  def test_runs_without_notifier
    source = FakeSource.new({ @pkg => [@vuln] })

    out   = StringIO.new
    count = StackWatch::Runner.call(@config, stdout: out, stderr: StringIO.new, source: source)

    assert_equal 1, count
    assert_match 'CVE-2024-99999', out.string
  end

  def test_summary_posted_even_when_zero_new
    source   = FakeSource.new({ @pkg => [] })
    notifier = FakeNotifier.new

    count = StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: StringIO.new,
                                             source: source, notifier: notifier)

    assert_equal 0, count
    assert_equal [0], notifier.summaries
  end

  def test_skips_vulns_older_than_max_age_days
    config = config_with(max_age_days: 30)
    fresh  = stub_vuln(id: 'CVE-FRESH', published: Time.now.utc - (5 * 86_400))
    stale  = stub_vuln(id: 'CVE-OLD',   published: Time.now.utc - (90 * 86_400))

    source   = FakeSource.new({ @pkg => [fresh, stale] })
    notifier = FakeNotifier.new

    count = StackWatch::Runner.call(config, stdout: StringIO.new, stderr: StringIO.new,
                                            source: source, notifier: notifier)

    assert_equal 1, count
    assert_equal(['CVE-FRESH'], notifier.notifications.map { |n| n[:vuln].id })
  end

  def test_skips_withdrawn_vulns_regardless_of_age
    fresh_withdrawn = stub_vuln(id: 'CVE-PULLED',
                                published: Time.now.utc - (1 * 86_400),
                                withdrawn: Time.now.utc)
    source   = FakeSource.new({ @pkg => [fresh_withdrawn] })
    notifier = FakeNotifier.new

    count = StackWatch::Runner.call(@config, stdout: StringIO.new, stderr: StringIO.new,
                                             source: source, notifier: notifier)

    assert_equal 0, count
    assert_empty notifier.notifications
  end

  def test_filtered_vulns_are_not_persisted_to_state
    config = config_with(max_age_days: 30)
    stale  = stub_vuln(id: 'CVE-OLD', published: Time.now.utc - (90 * 86_400))
    source = FakeSource.new({ @pkg => [stale] })

    StackWatch::Runner.call(config, stdout: StringIO.new, stderr: StringIO.new, source: source)

    return unless File.exist?(@state_path)

    data = JSON.parse(File.read(@state_path))
    refute_includes Array(data.dig('packages', 'PyPI/django')), 'CVE-OLD'
  end

  def test_max_age_disabled_includes_old_vulns
    config = config_with(max_age_days: nil)
    stale  = stub_vuln(id: 'CVE-OLD', published: Time.utc(2018, 9, 5))
    source = FakeSource.new({ @pkg => [stale] })
    notifier = FakeNotifier.new

    count = StackWatch::Runner.call(config, stdout: StringIO.new, stderr: StringIO.new,
                                            source: source, notifier: notifier)

    assert_equal 1, count
  end

  def test_vuln_with_unknown_publish_date_is_kept
    config  = config_with(max_age_days: 30)
    no_date = stub_vuln(id: 'CVE-NO-DATE', published: nil)
    source  = FakeSource.new({ @pkg => [no_date] })
    notifier = FakeNotifier.new

    count = StackWatch::Runner.call(config, stdout: StringIO.new, stderr: StringIO.new,
                                            source: source, notifier: notifier)

    assert_equal 1, count
  end

  private

  def config_with(**overrides)
    StackWatch::AppConfig.new(@config.to_h.merge(overrides))
  end
end
