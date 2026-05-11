require_relative '../test_helper'

class TestOSV < Minitest::Test
  OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'

  def pkg(name: 'django', ecosystem: 'PyPI', tier: 'standard')
    StackWatch::Package.new(name: name, ecosystem: ecosystem, tier: tier)
  end

  def stub_osv(body:, status: 200)
    stub_request(:post, OSV_BATCH_URL)
      .to_return(status: status, body: body, headers: { 'Content-Type' => 'application/json' })
  end

  def test_fetch_all_returns_normalized_vulns
    stub_osv(body: fixture('osv_querybatch_response.json'))
    p    = pkg
    res  = StackWatch::Sources::OSV.new([p]).fetch_all

    assert_equal 1, res[p].size
    v = res[p][0]
    assert_equal 'CVE-2024-27351', v.id
    assert_equal '7.5',            v.cvss_score
    assert_equal '3.2.25',         v.fixed
    assert_equal '>=3.2.0',        v.affected
    assert_match 'osv.dev',        v.url
  end

  def test_fetch_all_multiple_packages
    body = JSON.generate(results: [
                           { vulns: [{ 'id' => 'CVE-A', 'summary' => 'test', 'severity' => [], 'affected' => [] }] },
                           { vulns: [] }
                         ])
    stub_osv(body: body)

    p1 = pkg(name: 'django', ecosystem: 'PyPI')
    p2 = pkg(name: 'next',   ecosystem: 'npm')
    res = StackWatch::Sources::OSV.new([p1, p2]).fetch_all

    assert_equal 1, res[p1].size
    assert_equal 0, res[p2].size
  end

  def test_fetch_all_empty_packages_returns_empty_hash
    result = StackWatch::Sources::OSV.new([]).fetch_all
    assert_equal({}, result)
  end

  def test_empty_vulns_array_in_response
    stub_osv(body: JSON.generate(results: [{ vulns: [] }]))
    p   = pkg
    res = StackWatch::Sources::OSV.new([p]).fetch_all
    assert_equal [], res[p]
  end

  def test_missing_vulns_key_in_response
    stub_osv(body: JSON.generate(results: [{}]))
    p   = pkg
    res = StackWatch::Sources::OSV.new([p]).fetch_all
    assert_equal [], res[p]
  end

  def test_http_error_raises_osv_error
    stub_osv(body: 'Internal error', status: 500)
    assert_raises(StackWatch::Sources::OSVError) do
      StackWatch::Sources::OSV.new([pkg]).fetch_all
    end
  end

  def test_timeout_raises_osv_error
    stub_request(:post, OSV_BATCH_URL).to_timeout
    assert_raises(StackWatch::Sources::OSVError) do
      StackWatch::Sources::OSV.new([pkg]).fetch_all
    end
  end

  def test_cvss_extraction_v3
    body = JSON.generate(results: [{
                           vulns: [{
                             'id' => 'CVE-X',
                             'severity' => [{ 'type' => 'CVSS_V3', 'score' => '9.8' }],
                             'affected' => []
                           }]
                         }])
    stub_osv(body: body)
    p   = pkg
    res = StackWatch::Sources::OSV.new([p]).fetch_all
    assert_equal '9.8', res[p][0].cvss_score
  end

  def test_cvss_falls_back_to_na
    body = JSON.generate(results: [{
                           vulns: [{ 'id' => 'CVE-X', 'affected' => [] }]
                         }])
    stub_osv(body: body)
    p   = pkg
    res = StackWatch::Sources::OSV.new([p]).fetch_all
    assert_equal 'N/A', res[p][0].cvss_score
  end

  def test_no_fixed_version_returns_nil
    body = JSON.generate(results: [{
                           vulns: [{
                             'id' => 'CVE-X',
                             'affected' => [{ 'ranges' => [{ 'events' => [{ 'introduced' => '1.0' }] }] }]
                           }]
                         }])
    stub_osv(body: body)
    p   = pkg
    res = StackWatch::Sources::OSV.new([p]).fetch_all
    assert_nil res[p][0].fixed
  end
end
