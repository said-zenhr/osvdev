require_relative 'test_helper'
require 'tmpdir'
require 'fileutils'
require 'stackwatch/cli'

class TestCLI < Minitest::Test
  def setup
    @tmpdir = Dir.mktmpdir
    @orig_dir = Dir.pwd
    Dir.chdir(@tmpdir)
  end

  def teardown
    Dir.chdir(@orig_dir)
    FileUtils.rm_rf(@tmpdir)
  end

  def test_init_creates_parseable_yaml
    capture_io { StackWatch::CLI.start(['init']) }

    assert File.exist?('stack.yml'), 'stack.yml should be created'
    parsed = Psych.safe_load_file('stack.yml')
    assert parsed.is_a?(Hash), 'stack.yml should parse as a YAML mapping'
    assert parsed.key?('packages'), 'stack.yml should contain a packages key'
  end

  def test_init_refuses_to_overwrite_without_force
    File.write('stack.yml', 'existing content')

    ex = assert_raises(SystemExit) do
      capture_io { StackWatch::CLI.start(['init']) }
    end
    assert_equal 1, ex.status
    assert_equal 'existing content', File.read('stack.yml')
  end

  def test_init_force_overwrites
    File.write('stack.yml', 'old content')

    capture_io { StackWatch::CLI.start(['init', '--force']) }

    refute_equal 'old content', File.read('stack.yml')
    parsed = Psych.safe_load_file('stack.yml')
    assert parsed.is_a?(Hash)
  end

  def test_run_with_missing_config_exits_with_error
    ex = assert_raises(SystemExit) do
      capture_io { StackWatch::CLI.start(['run', '--config', '/nonexistent/stack.yml']) }
    end
    assert_equal 1, ex.status
  end
end
