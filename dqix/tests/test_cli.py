"""Test CLI features."""

import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock

from ..cli import cli, check

@pytest.fixture
def runner():
    """Create CLI runner."""
    return CliRunner()

def test_version(runner):
    """Test version command."""
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "DQIX" in result.output

def test_help(runner):
    """Test help command."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.output
    assert "Options" in result.output
    assert "Commands" in result.output

def test_check_help(runner):
    """Test check command help."""
    result = runner.invoke(cli, ["check", "--help"])
    assert result.exit_code == 0
    assert "Usage" in result.output
    assert "Options" in result.output
    assert "Probes" in result.output

@patch("dqix.cli.Runner")
def test_check_domain(mock_runner, runner):
    """Test checking a single domain."""
    mock_runner.return_value.run.return_value = {
        "score": 0.8,
        "details": {"tls": 0.9, "headers": 0.7}
    }
    
    result = runner.invoke(cli, ["check", "example.com"])
    assert result.exit_code == 0
    assert "Score: 0.8" in result.output
    assert "TLS: 0.9" in result.output
    assert "Headers: 0.7" in result.output

@patch("dqix.cli.Runner")
def test_check_multiple_domains(mock_runner, runner):
    """Test checking multiple domains."""
    mock_runner.return_value.run.side_effect = [
        {"score": 0.8, "details": {"tls": 0.9}},
        {"score": 0.7, "details": {"tls": 0.8}}
    ]
    
    result = runner.invoke(cli, ["check", "example.com", "example.org"])
    assert result.exit_code == 0
    assert "example.com" in result.output
    assert "example.org" in result.output
    assert "Score: 0.8" in result.output
    assert "Score: 0.7" in result.output

@patch("dqix.cli.Runner")
def test_check_specific_probes(mock_runner, runner):
    """Test checking specific probes."""
    mock_runner.return_value.run.return_value = {
        "score": 0.8,
        "details": {"tls": 0.9, "headers": 0.7}
    }
    
    result = runner.invoke(cli, ["check", "example.com", "--probes", "tls,headers"])
    assert result.exit_code == 0
    mock_runner.return_value.run.assert_called_once()
    args = mock_runner.return_value.run.call_args[1]
    assert set(args["probes"]) == {"tls", "headers"}

@patch("dqix.cli.Runner")
def test_check_output_formats(mock_runner, runner):
    """Test different output formats."""
    mock_runner.return_value.run.return_value = {
        "score": 0.8,
        "details": {"tls": 0.9}
    }
    
    # Test JSON format
    result = runner.invoke(cli, ["check", "example.com", "--format", "json"])
    assert result.exit_code == 0
    assert '"score": 0.8' in result.output
    assert '"tls": 0.9' in result.output
    
    # Test YAML format
    result = runner.invoke(cli, ["check", "example.com", "--format", "yaml"])
    assert result.exit_code == 0
    assert "score: 0.8" in result.output
    assert "tls: 0.9" in result.output

@patch("dqix.cli.Runner")
def test_check_timeout(mock_runner, runner):
    """Test timeout setting."""
    mock_runner.return_value.run.return_value = {
        "score": 0.8,
        "details": {"tls": 0.9}
    }
    
    result = runner.invoke(cli, ["check", "example.com", "--timeout", "30"])
    assert result.exit_code == 0
    mock_runner.return_value.run.assert_called_once()
    args = mock_runner.return_value.run.call_args[1]
    assert args["timeout"] == 30

@patch("dqix.cli.Runner")
def test_check_max_retries(mock_runner, runner):
    """Test max retries setting."""
    mock_runner.return_value.run.return_value = {
        "score": 0.8,
        "details": {"tls": 0.9}
    }
    
    result = runner.invoke(cli, ["check", "example.com", "--max-retries", "3"])
    assert result.exit_code == 0
    mock_runner.return_value.run.assert_called_once()
    args = mock_runner.return_value.run.call_args[1]
    assert args["max_retries"] == 3

@patch("dqix.cli.Runner")
def test_check_verbose(mock_runner, runner):
    """Test verbose output."""
    mock_runner.return_value.run.return_value = {
        "score": 0.8,
        "details": {"tls": 0.9}
    }
    
    result = runner.invoke(cli, ["check", "example.com", "--verbose"])
    assert result.exit_code == 0
    assert "Running probe" in result.output
    assert "Completed probe" in result.output

@patch("dqix.cli.Runner")
def test_check_plugins(mock_runner, runner):
    """Test plugin loading."""
    mock_runner.return_value.run.return_value = {
        "score": 0.8,
        "details": {"whois": 0.9, "sri": 0.7}
    }
    
    result = runner.invoke(cli, ["check", "example.com", "--plugins", "whois,sri"])
    assert result.exit_code == 0
    mock_runner.return_value.run.assert_called_once()
    args = mock_runner.return_value.run.call_args[1]
    assert set(args["plugins"]) == {"whois", "sri"}

@patch("dqix.cli.Runner")
def test_check_output_file(mock_runner, runner, tmp_path):
    """Test output to file."""
    mock_runner.return_value.run.return_value = {
        "score": 0.8,
        "details": {"tls": 0.9}
    }
    
    output_file = tmp_path / "results.json"
    result = runner.invoke(cli, ["check", "example.com", "--output", str(output_file)])
    assert result.exit_code == 0
    assert output_file.exists()
    content = output_file.read_text()
    assert '"score": 0.8' in content
    assert '"tls": 0.9' in content

@patch("dqix.cli.Runner")
def test_check_error_handling(mock_runner, runner):
    """Test error handling."""
    mock_runner.return_value.run.side_effect = Exception("Test error")
    
    result = runner.invoke(cli, ["check", "example.com"])
    assert result.exit_code == 1
    assert "Error" in result.output
    assert "Test error" in result.output

@patch("dqix.cli.Runner")
def test_check_invalid_domain(mock_runner, runner):
    """Test invalid domain handling."""
    mock_runner.return_value.run.return_value = {
        "score": 0.0,
        "details": {"error": "Invalid domain"}
    }
    
    result = runner.invoke(cli, ["check", "invalid"])
    assert result.exit_code == 0
    assert "Score: 0.0" in result.output
    assert "Invalid domain" in result.output

@patch("dqix.cli.Runner")
def test_check_timeout_error(mock_runner, runner):
    """Test timeout error handling."""
    mock_runner.return_value.run.side_effect = TimeoutError("Connection timed out")
    
    result = runner.invoke(cli, ["check", "example.com"])
    assert result.exit_code == 1
    assert "Error" in result.output
    assert "Connection timed out" in result.output

@patch("dqix.cli.Runner")
def test_check_network_error(mock_runner, runner):
    """Test network error handling."""
    mock_runner.return_value.run.side_effect = ConnectionError("Network error")
    
    result = runner.invoke(cli, ["check", "example.com"])
    assert result.exit_code == 1
    assert "Error" in result.output
    assert "Network error" in result.output 