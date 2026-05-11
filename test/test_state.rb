require_relative 'test_helper'
require 'tmpdir'
require 'fileutils'

class TestState < Minitest::Test
  def setup
    @tmpdir   = Dir.mktmpdir
    @path     = File.join(@tmpdir, 'state.json')
    @pkg    = StackWatch::Package.new(name: 'django', ecosystem: 'PyPI', tier: 'standard')
    @vuln_a = stub_vuln(id: 'CVE-2024-001', summary: 'A')
    @vuln_b = stub_vuln(id: 'CVE-2024-002', summary: 'B')
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  def test_load_missing_file_starts_fresh
    refute File.exist?(@path)
    state = StackWatch::State.load(@path)
    # No exception; empty state treats all vulns as new
    assert_equal [@vuln_a], state.diff(@pkg, [@vuln_a])
  end

  def test_diff_returns_new_vulns_when_state_empty
    state = StackWatch::State.load(@path)
    result = state.diff(@pkg, [@vuln_a, @vuln_b])
    assert_equal [@vuln_a, @vuln_b], result
  end

  def test_diff_excludes_seen_vulns
    state = StackWatch::State.load(fixture_path('state_v1.json'))
    django_pkg = StackWatch::Package.new(name: 'django', ecosystem: 'PyPI', tier: 'critical')
    result = state.diff(django_pkg, [
                          stub_vuln(id: 'CVE-2024-27351'), # already seen
                          stub_vuln(id: 'CVE-2024-99999') # new
                        ])
    assert_equal 1, result.size
    assert_equal 'CVE-2024-99999', result[0].id
  end

  def test_diff_returns_empty_when_all_seen
    state = StackWatch::State.load(fixture_path('state_v1.json'))
    django_pkg = StackWatch::Package.new(name: 'django', ecosystem: 'PyPI', tier: 'critical')
    assert_equal [], state.diff(django_pkg, [stub_vuln(id: 'CVE-2024-27351')])
  end

  def test_mark_seen_then_diff_returns_empty
    state = StackWatch::State.load(@path)
    state.mark_seen(@pkg, [@vuln_a])
    assert_equal [], state.diff(@pkg, [@vuln_a])
  end

  def test_mark_seen_deduplicates
    state = StackWatch::State.load(@path)
    state.mark_seen(@pkg, [@vuln_a])
    state.mark_seen(@pkg, [@vuln_a])
    state.persist

    StackWatch::State.load(@path)
    data = JSON.parse(File.read(@path))
    assert_equal 1, data.dig('packages', 'PyPI/django').size
  end

  def test_persist_writes_valid_json
    state = StackWatch::State.load(@path)
    state.mark_seen(@pkg, [@vuln_a])
    state.persist

    data = JSON.parse(File.read(@path))
    assert_equal 1, data['version']
    assert_includes data.dig('packages', 'PyPI/django'), 'CVE-2024-001'
  end

  def test_persist_atomic_no_tmp_left
    state = StackWatch::State.load(@path)
    state.persist

    tmp_files = Dir.glob("#{@path}.tmp.*")
    assert_empty tmp_files
  end

  def test_load_corrupt_json_starts_fresh
    File.write(@path, 'not json {{{{')
    state = StackWatch::State.load(@path)
    result = state.diff(@pkg, [@vuln_a])
    assert_equal [@vuln_a], result
  end

  def test_mark_seen_caps_at_max
    state = StackWatch::State.load(@path)
    big_batch = (1..600).map { |i| stub_vuln(id: "CVE-#{i}") }
    state.mark_seen(@pkg, big_batch)
    state.persist

    data = JSON.parse(File.read(@path))
    assert_equal StackWatch::State::MAX_SEEN_PER_PACKAGE, data.dig('packages', 'PyPI/django').size
  end

  def test_mark_seen_keeps_most_recent
    state = StackWatch::State.load(@path)
    big_batch = (1..600).map { |i| stub_vuln(id: "CVE-#{i}") }
    state.mark_seen(@pkg, big_batch)

    data_ids = state.instance_variable_get(:@data).dig('packages', 'PyPI/django')
    assert_includes data_ids, 'CVE-600'
    refute_includes data_ids, 'CVE-1'
  end

  def test_persist_creates_lockfile
    state = StackWatch::State.load(@path)
    state.persist

    assert File.exist?("#{@path}.lock")
  end
end
