require_relative "test_helper"

class TestVuln < Minitest::Test
  FULL_RECORD = {
    "id"       => "CVE-2024-12345",
    "summary"  => "SQL injection in query builder",
    "severity" => [{ "type" => "CVSS_V3", "score" => "9.8" }],
    "affected" => [
      { "ranges" => [{ "events" => [{ "introduced" => "1.0" }, { "fixed" => "1.4.2" }] }] }
    ]
  }.freeze

  def test_from_osv_happy_path
    vuln = StackWatch::Vuln.from_osv(FULL_RECORD)

    assert_equal "CVE-2024-12345", vuln.id
    assert_equal "SQL injection in query builder", vuln.summary
    assert_equal "9.8", vuln.cvss_score
    assert_equal ">=1.0", vuln.affected
    assert_equal "1.4.2", vuln.fixed
    assert_equal "https://osv.dev/vulnerability/CVE-2024-12345", vuln.url
  end

  def test_url_constructed_from_id
    vuln = StackWatch::Vuln.from_osv({ "id" => "GHSA-abcd-1234-wxyz" })
    assert_equal "https://osv.dev/vulnerability/GHSA-abcd-1234-wxyz", vuln.url
  end

  def test_missing_severity_falls_back_to_database_specific
    record = {
      "id"                => "CVE-2024-00001",
      "summary"           => "test",
      "database_specific" => { "cvss" => { "score" => "7.5" } }
    }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_equal "7.5", vuln.cvss_score
  end

  def test_no_severity_at_all_returns_na
    record = { "id" => "CVE-2024-00002", "summary" => "test" }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_equal "N/A", vuln.cvss_score
  end

  def test_missing_summary_falls_back_to_details
    record = {
      "id"      => "CVE-2024-00003",
      "details" => "A very long description of the vulnerability that should be truncated."
    }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_equal record["details"], vuln.summary
  end

  def test_missing_summary_truncates_long_details
    long_details = "x" * 500
    record = { "id" => "CVE-2024-00004", "details" => long_details }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_equal 200, vuln.summary.length
  end

  def test_missing_summary_and_details_returns_empty
    record = { "id" => "CVE-2024-00005" }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_equal "", vuln.summary
  end

  def test_multiple_introduced_events
    record = {
      "id"       => "CVE-2024-00006",
      "summary"  => "test",
      "affected" => [
        { "ranges" => [{ "events" => [
          { "introduced" => "1.0" },
          { "introduced" => "2.0" },
          { "fixed" => "2.1" }
        ] }] }
      ]
    }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_equal ">=1.0, >=2.0", vuln.affected
  end

  def test_no_fixed_event_returns_nil
    record = {
      "id"       => "CVE-2024-00007",
      "summary"  => "test",
      "affected" => [
        { "ranges" => [{ "events" => [{ "introduced" => "0" }] }] }
      ]
    }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_nil vuln.fixed
  end

  def test_empty_affected_array
    record = { "id" => "CVE-2024-00008", "summary" => "test", "affected" => [] }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_equal "unknown", vuln.affected
    assert_nil vuln.fixed
  end

  def test_no_affected_key_at_all
    record = { "id" => "CVE-2024-00009", "summary" => "test" }
    vuln = StackWatch::Vuln.from_osv(record)
    assert_equal "unknown", vuln.affected
    assert_nil vuln.fixed
  end
end
