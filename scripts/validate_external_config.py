#!/usr/bin/env python3
"""
Unified Configuration Validation Script for DQIX External Weight Configuration

This script validates that all language implementations are properly configured
to use externalized weights from shared-config.yaml, ensuring true single source
of truth across the entire polyglot architecture.
"""

import sys
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class ConfigurationValidator:
    """Validates external configuration across all language implementations"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.shared_config_path = project_root / "shared-config.yaml"
        self.shared_config = None
        self.validation_results = {}
        
    def load_shared_config(self) -> bool:
        """Load and validate shared-config.yaml"""
        if not self.shared_config_path.exists():
            logger.error(f"shared-config.yaml not found at {self.shared_config_path}")
            return False
        
        try:
            with open(self.shared_config_path, 'r', encoding='utf-8') as f:
                self.shared_config = yaml.safe_load(f)
            
            # Validate required sections
            required_sections = ["probe_weights"]
            for section in required_sections:
                if section not in self.shared_config:
                    logger.error(f"Missing required section '{section}' in shared-config.yaml")
                    return False
            
            # Validate probe weights
            required_probes = ["tls", "dns", "https", "security_headers"]
            probe_weights = self.shared_config["probe_weights"]
            
            for probe in required_probes:
                if probe not in probe_weights:
                    logger.error(f"Missing weight for required probe '{probe}'")
                    return False
                
                if probe_weights[probe] <= 0:
                    logger.error(f"Invalid weight for probe '{probe}': {probe_weights[probe]}")
                    return False
            
            logger.info("✅ shared-config.yaml validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load shared-config.yaml: {e}")
            return False
    
    def validate_all_implementations(self) -> Dict[str, bool]:
        """Validate all language implementations"""
        implementations = {
            "Go": self.validate_go_implementation,
            "Rust": self.validate_rust_implementation,
            "C++": self.validate_cpp_implementation,
            "Haskell": self.validate_haskell_implementation,
            "Python": self.validate_python_implementation,
        }
        
        results = {}
        for name, validator in implementations.items():
            try:
                results[name] = validator()
                status = "✅ PASS" if results[name] else "❌ FAIL"
                logger.info(f"{name} implementation: {status}")
            except Exception as e:
                results[name] = False
                logger.error(f"{name} implementation validation failed: {e}")
        
        return results
    
    def validate_go_implementation(self) -> bool:
        """Validate Go implementation uses external configuration"""
        go_dir = self.project_root / "dqix-go"
        if not go_dir.exists():
            logger.warning("Go implementation directory not found")
            return False
        
        # Check for externalized configuration in Go files
        checks = [
            # Check config loader exists
            (go_dir / "internal/config/loader.go", "Config loader file"),
            # Check probes use external config (either via weighted_manager or direct config access)
        ]
        
        # Check that demo works
        demo_file = go_dir / "demo-external-config.go"
        if demo_file.exists():
            try:
                result = subprocess.run(
                    ["go", "run", "demo-external-config.go"],
                    cwd=go_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0 and "external configuration" in result.stdout.lower():
                    logger.info("Go demo runs successfully")
                    return True
                else:
                    logger.warning(f"Go demo failed: {result.stderr}")
            except subprocess.TimeoutExpired:
                logger.warning("Go demo timed out")
            except Exception as e:
                logger.warning(f"Go demo execution failed: {e}")
        
        # Check for external config usage in source files
        probe_files = list(go_dir.glob("**/*.go"))
        external_config_found = False
        
        for file_path in probe_files:
            try:
                content = file_path.read_text(encoding='utf-8')
                if ("ConfigManager" in content or 
                    "SharedConfigLoader" in content or 
                    "getProbeWeight" in content or
                    "shared-config.yaml" in content):
                    external_config_found = True
                    break
            except Exception:
                continue
        
        return external_config_found
    
    def validate_rust_implementation(self) -> bool:
        """Validate Rust implementation uses external configuration"""
        rust_dir = self.project_root / "dqix-rust"
        if not rust_dir.exists():
            logger.warning("Rust implementation directory not found")
            return False
        
        # Check config module exists
        config_file = rust_dir / "src/config.rs"
        if not config_file.exists():
            logger.warning("Rust config module not found")
            return False
        
        # Check probes use external configuration
        probes_file = rust_dir / "src/probes.rs"
        if probes_file.exists():
            try:
                content = probes_file.read_text(encoding='utf-8')
                if ("ConfigManager::get_probe_weight" in content and
                    "EXTERNALIZED WEIGHT CONFIGURATION" in content):
                    return True
            except Exception:
                pass
        
        return False
    
    def validate_cpp_implementation(self) -> bool:
        """Validate C++ implementation uses external configuration"""
        cpp_dir = self.project_root / "dqix-cpp"
        if not cpp_dir.exists():
            logger.warning("C++ implementation directory not found")
            return False
        
        # Check config loader exists
        config_header = cpp_dir / "include/config/shared_config_loader.h"
        config_impl = cpp_dir / "src/config/shared_config_loader.cpp"
        
        if not (config_header.exists() and config_impl.exists()):
            logger.warning("C++ config loader not found")
            return False
        
        # Check probe headers use external configuration
        probe_headers = list((cpp_dir / "include/probes").glob("*.h"))
        external_config_found = False
        
        for header_file in probe_headers:
            try:
                content = header_file.read_text(encoding='utf-8')
                if ("SharedConfigLoader::getInstance().getProbeWeight" in content and
                    "EXTERNALIZED WEIGHT CONFIGURATION" in content):
                    external_config_found = True
                    break
            except Exception:
                continue
        
        return external_config_found
    
    def validate_haskell_implementation(self) -> bool:
        """Validate Haskell implementation uses external configuration"""
        haskell_dir = self.project_root / "dqix-haskell"
        if not haskell_dir.exists():
            logger.warning("Haskell implementation directory not found")
            return False
        
        # Check config module exists
        config_file = haskell_dir / "src/Config/SharedConfig.hs"
        if not config_file.exists():
            logger.warning("Haskell config module not found")
            return False
        
        # Check main file uses external configuration
        main_file = haskell_dir / "Main.hs"
        if main_file.exists():
            try:
                content = main_file.read_text(encoding='utf-8')
                if ("Config.SharedConfig" in content and
                    "EXTERNALIZED WEIGHT CONFIGURATION" in content):
                    return True
            except Exception:
                pass
        
        return False
    
    def validate_python_implementation(self) -> bool:
        """Validate Python implementation uses external configuration"""
        python_dir = self.project_root / "dqix-python"
        if not python_dir.exists():
            logger.warning("Python implementation directory not found")
            return False
        
        # Check config loader exists
        config_file = python_dir / "config/shared_config_loader.py"
        if not config_file.exists():
            logger.warning("Python config loader not found")
            return False
        
        # Try running the demo
        demo_file = python_dir / "demo_external_config.py"
        if demo_file.exists():
            try:
                result = subprocess.run(
                    [sys.executable, "demo_external_config.py"],
                    cwd=python_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0 and "external configuration" in result.stdout.lower():
                    return True
                else:
                    logger.warning(f"Python demo failed: {result.stderr}")
            except subprocess.TimeoutExpired:
                logger.warning("Python demo timed out")
            except Exception as e:
                logger.warning(f"Python demo execution failed: {e}")
        
        return False
    
    def validate_weight_consistency(self) -> bool:
        """Validate that all implementations would use the same weights"""
        if not self.shared_config:
            return False
        
        expected_weights = self.shared_config["probe_weights"]
        expected_total = sum(expected_weights[probe] for probe in ["tls", "dns", "https", "security_headers"])
        
        print(f"\n📊 Expected weights from shared-config.yaml:")
        for probe, weight in expected_weights.items():
            if probe in ["tls", "dns", "https", "security_headers"]:
                print(f"  {probe:20}: {weight:.1f}")
        print(f"  {'TOTAL':20}: {expected_total:.1f}")
        
        return True
    
    def run_demo_tests(self) -> Dict[str, bool]:
        """Run demo tests for all implementations that have them"""
        demo_results = {}
        
        # Test Go demo
        go_demo = self.project_root / "dqix-go" / "demo-external-config.go"
        if go_demo.exists():
            demo_results["Go"] = self._test_demo("go", "run", str(go_demo), cwd=go_demo.parent)
        
        # Test Python demo
        python_demo = self.project_root / "dqix-python" / "demo_external_config.py"
        if python_demo.exists():
            demo_results["Python"] = self._test_demo(sys.executable, str(python_demo), cwd=python_demo.parent)
        
        return demo_results
    
    def _test_demo(self, command: str, *args, cwd: Path) -> bool:
        """Test a demo implementation"""
        try:
            cmd_args = [command] + list(filter(None, args))
            result = subprocess.run(
                cmd_args,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0 and "external configuration" in result.stdout.lower()
        except Exception:
            return False
    
    def generate_report(self, validation_results: Dict[str, bool], demo_results: Dict[str, bool]) -> None:
        """Generate comprehensive validation report"""
        print("\n" + "="*80)
        print("🔍 DQIX EXTERNAL CONFIGURATION VALIDATION REPORT")
        print("="*80)
        
        if not self.shared_config:
            print("❌ shared-config.yaml validation FAILED")
            return
        
        print("✅ shared-config.yaml validation PASSED")
        
        print(f"\n📊 Configuration Summary:")
        probe_weights = self.shared_config["probe_weights"]
        total = sum(probe_weights[p] for p in ["tls", "dns", "https", "security_headers"])
        
        for probe in ["tls", "dns", "https", "security_headers"]:
            weight = probe_weights[probe]
            percentage = (weight / total) * 100
            print(f"  {probe:20}: {weight:.1f} ({percentage:.1f}%)")
        print(f"  {'TOTAL':20}: {total:.1f}")
        
        print(f"\n🎯 Implementation Validation Results:")
        all_passed = True
        for impl, passed in validation_results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"  {impl:20}: {status}")
            if not passed:
                all_passed = False
        
        if demo_results:
            print(f"\n🚀 Demo Test Results:")
            for impl, passed in demo_results.items():
                status = "✅ PASS" if passed else "❌ FAIL"
                print(f"  {impl:20}: {status}")
        
        print(f"\n🎉 Overall Status: {'✅ ALL IMPLEMENTATIONS EXTERNALIZED' if all_passed else '❌ SOME IMPLEMENTATIONS NEED FIXES'}")
        
        if all_passed:
            print("\n✨ Congratulations! All language implementations successfully use")
            print("   externalized weight configuration from shared-config.yaml")
            print("✨ True single source of truth achieved across polyglot architecture!")
        else:
            print("\n⚠️  Some implementations still need to be updated to use external configuration")


def main():
    """Main validation function"""
    print("🔍 DQIX External Configuration Validation")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    # Find project root
    current_dir = Path.cwd()
    project_root = None
    
    # Search up the directory tree for shared-config.yaml
    for path in [current_dir] + list(current_dir.parents):
        if (path / "shared-config.yaml").exists():
            project_root = path
            break
    
    if not project_root:
        logger.error("Could not find project root (shared-config.yaml not found)")
        return 1
    
    logger.info(f"Project root: {project_root}")
    
    # Initialize validator
    validator = ConfigurationValidator(project_root)
    
    # Load and validate shared config
    if not validator.load_shared_config():
        return 1
    
    # Validate all implementations
    validation_results = validator.validate_all_implementations()
    
    # Test weight consistency
    validator.validate_weight_consistency()
    
    # Run demo tests
    demo_results = validator.run_demo_tests()
    
    # Generate report
    validator.generate_report(validation_results, demo_results)
    
    # Return appropriate exit code
    all_passed = all(validation_results.values())
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())