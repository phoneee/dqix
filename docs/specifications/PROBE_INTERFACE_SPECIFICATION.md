# DQIX Probe Interface Specification

## Overview

This document defines the standardized probe interface that ALL language implementations MUST follow. This ensures consistent behavior, easy extension, and maintainable code across the polyglot architecture.

## Core Probe Interface

### Universal Probe Contract

Every probe implementation across all languages MUST implement this interface:

```typescript
// TypeScript/JavaScript pseudo-interface
interface Probe {
  // Metadata
  id: string;                    // Unique probe identifier (e.g., "tls", "dns")
  name: string;                  // Human-readable name
  description: string;           // Detailed description
  category: ProbeCategory;       // security|infrastructure|performance|compliance
  version: string;               // Probe version for compatibility
  
  // Configuration
  default_config: ProbeConfig;   // Default configuration
  config_schema: ConfigSchema;   // Configuration validation schema
  
  // Core Methods
  execute(domain: string, config: ProbeConfig): Promise<ProbeResult>;
  validate_config(config: ProbeConfig): ValidationResult;
  get_requirements(): string[];   // External dependencies (e.g., "openssl")
  
  // Optional Methods
  supports_batch?(): boolean;     // Can handle multiple domains
  get_metrics?(): ProbeMetrics;   // Performance/diagnostic metrics
}

// Supporting Types
type ProbeCategory = "security" | "infrastructure" | "performance" | "compliance";

interface ProbeConfig {
  enabled: boolean;
  timeout: number;
  [key: string]: any;  // Probe-specific configuration
}

interface ProbeResult {
  id: string;
  name: string;
  category: ProbeCategory;
  score: number;                 // 0-100
  status: ProbeStatus;           // pass|warn|fail|error
  details: string;               // Human-readable summary
  metrics: Record<string, any>;  // Detailed measurements
  recommendations: string[];     // Specific remediation advice
  execution_time_ms: number;     // Performance tracking
  timestamp: string;             // ISO 8601 timestamp
  error?: ProbeError;           // Error details if status = error
}

type ProbeStatus = "pass" | "warn" | "fail" | "error";

interface ProbeError {
  code: string;
  message: string;
  details?: any;
}
```

## Language-Specific Implementations

### Python (Reference Implementation)

```python
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import time
from datetime import datetime

class ProbeCategory(Enum):
    SECURITY = "security"
    INFRASTRUCTURE = "infrastructure"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"

class ProbeStatus(Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"

@dataclass
class ProbeResult:
    id: str
    name: str
    category: ProbeCategory
    score: int  # 0-100
    status: ProbeStatus
    details: str
    metrics: Dict[str, Any]
    recommendations: List[str]
    execution_time_ms: int
    timestamp: str
    error: Optional[Dict[str, Any]] = None

@dataclass
class ProbeConfig:
    enabled: bool = True
    timeout: int = 30
    
class Probe(ABC):
    def __init__(self):
        self.id = self._get_id()
        self.name = self._get_name()
        self.description = self._get_description()
        self.category = self._get_category()
        self.version = self._get_version()
    
    @abstractmethod
    def _get_id(self) -> str:
        pass
    
    @abstractmethod
    def _get_name(self) -> str:
        pass
    
    @abstractmethod
    def _get_description(self) -> str:
        pass
    
    @abstractmethod
    def _get_category(self) -> ProbeCategory:
        pass
    
    @abstractmethod
    def _get_version(self) -> str:
        pass
    
    @abstractmethod
    async def execute(self, domain: str, config: ProbeConfig) -> ProbeResult:
        pass
    
    def validate_config(self, config: ProbeConfig) -> bool:
        return isinstance(config.enabled, bool) and isinstance(config.timeout, int)
    
    def get_requirements(self) -> List[str]:
        return []
    
    def supports_batch(self) -> bool:
        return False
```

### Go Implementation

```go
package probes

import (
    "context"
    "time"
)

type ProbeCategory string

const (
    CategorySecurity       ProbeCategory = "security"
    CategoryInfrastructure ProbeCategory = "infrastructure"
    CategoryPerformance    ProbeCategory = "performance"
    CategoryCompliance     ProbeCategory = "compliance"
)

type ProbeStatus string

const (
    StatusPass  ProbeStatus = "pass"
    StatusWarn  ProbeStatus = "warn"
    StatusFail  ProbeStatus = "fail"
    StatusError ProbeStatus = "error"
)

type ProbeConfig struct {
    Enabled bool          `json:"enabled"`
    Timeout time.Duration `json:"timeout"`
    Extra   map[string]interface{} `json:"extra,omitempty"`
}

type ProbeResult struct {
    ID              string                 `json:"id"`
    Name            string                 `json:"name"`
    Category        ProbeCategory          `json:"category"`
    Score           int                    `json:"score"`
    Status          ProbeStatus            `json:"status"`
    Details         string                 `json:"details"`
    Metrics         map[string]interface{} `json:"metrics"`
    Recommendations []string               `json:"recommendations"`
    ExecutionTimeMs int64                  `json:"execution_time_ms"`
    Timestamp       time.Time              `json:"timestamp"`
    Error           *ProbeError            `json:"error,omitempty"`
}

type ProbeError struct {
    Code    string      `json:"code"`
    Message string      `json:"message"`
    Details interface{} `json:"details,omitempty"`
}

type Probe interface {
    ID() string
    Name() string
    Description() string
    Category() ProbeCategory
    Version() string
    
    Execute(ctx context.Context, domain string, config ProbeConfig) (*ProbeResult, error)
    ValidateConfig(config ProbeConfig) error
    GetRequirements() []string
    SupportsBatch() bool
}

// Base probe implementation
type BaseProbe struct {
    id          string
    name        string
    description string
    category    ProbeCategory
    version     string
}

func (p *BaseProbe) ID() string { return p.id }
func (p *BaseProbe) Name() string { return p.name }
func (p *BaseProbe) Description() string { return p.description }
func (p *BaseProbe) Category() ProbeCategory { return p.category }
func (p *BaseProbe) Version() string { return p.version }
func (p *BaseProbe) GetRequirements() []string { return []string{} }
func (p *BaseProbe) SupportsBatch() bool { return false }

func (p *BaseProbe) ValidateConfig(config ProbeConfig) error {
    if config.Timeout <= 0 {
        return fmt.Errorf("timeout must be positive")
    }
    return nil
}
```

### Rust Implementation

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeCategory {
    #[serde(rename = "security")]
    Security,
    #[serde(rename = "infrastructure")]
    Infrastructure,
    #[serde(rename = "performance")]
    Performance,
    #[serde(rename = "compliance")]
    Compliance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeStatus {
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "error")]
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    pub enabled: bool,
    pub timeout: Duration,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeResult {
    pub id: String,
    pub name: String,
    pub category: ProbeCategory,
    pub score: u8, // 0-100
    pub status: ProbeStatus,
    pub details: String,
    pub metrics: HashMap<String, serde_json::Value>,
    pub recommendations: Vec<String>,
    pub execution_time_ms: u64,
    pub timestamp: SystemTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProbeError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[async_trait]
pub trait Probe: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn category(&self) -> ProbeCategory;
    fn version(&self) -> &str;
    
    async fn execute(&self, domain: &str, config: &ProbeConfig) -> Result<ProbeResult, Box<dyn std::error::Error>>;
    fn validate_config(&self, config: &ProbeConfig) -> Result<(), String>;
    fn get_requirements(&self) -> Vec<String> { vec![] }
    fn supports_batch(&self) -> bool { false }
}

pub struct BaseProbe {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ProbeCategory,
    pub version: String,
}

impl BaseProbe {
    pub fn new(id: String, name: String, description: String, category: ProbeCategory, version: String) -> Self {
        Self { id, name, description, category, version }
    }
}

#[async_trait]
impl Probe for BaseProbe {
    fn id(&self) -> &str { &self.id }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn category(&self) -> ProbeCategory { self.category.clone() }
    fn version(&self) -> &str { &self.version }
    
    async fn execute(&self, _domain: &str, _config: &ProbeConfig) -> Result<ProbeResult, Box<dyn std::error::Error>> {
        unimplemented!("Base probe cannot be executed directly")
    }
    
    fn validate_config(&self, config: &ProbeConfig) -> Result<(), String> {
        if config.timeout.as_secs() == 0 {
            Err("Timeout must be greater than 0".to_string())
        } else {
            Ok(())
        }
    }
}
```

### Haskell Implementation

```haskell
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module DQIX.Probes.Interface where

import Data.Aeson
import Data.Time
import GHC.Generics
import qualified Data.Map.Strict as Map
import qualified Data.Text as T

-- Core Types
data ProbeCategory = Security | Infrastructure | Performance | Compliance
    deriving (Show, Eq, Generic)

instance ToJSON ProbeCategory where
    toJSON Security = "security"
    toJSON Infrastructure = "infrastructure"
    toJSON Performance = "performance"
    toJSON Compliance = "compliance"

data ProbeStatus = Pass | Warn | Fail | Error
    deriving (Show, Eq, Generic)

instance ToJSON ProbeStatus where
    toJSON Pass = "pass"
    toJSON Warn = "warn"
    toJSON Fail = "fail"
    toJSON Error = "error"

data ProbeConfig = ProbeConfig
    { enabled :: Bool
    , timeout :: Int
    , extra :: Map.Map T.Text Value
    } deriving (Show, Generic)

instance ToJSON ProbeConfig
instance FromJSON ProbeConfig

data ProbeResult = ProbeResult
    { resultId :: T.Text
    , resultName :: T.Text
    , resultCategory :: ProbeCategory
    , resultScore :: Int
    , resultStatus :: ProbeStatus
    , resultDetails :: T.Text
    , resultMetrics :: Map.Map T.Text Value
    , resultRecommendations :: [T.Text]
    , resultExecutionTimeMs :: Int
    , resultTimestamp :: UTCTime
    , resultError :: Maybe ProbeError
    } deriving (Show, Generic)

instance ToJSON ProbeResult where
    toJSON = genericToJSON defaultOptions
        { fieldLabelModifier = \x -> case x of
            "resultId" -> "id"
            "resultName" -> "name"
            "resultCategory" -> "category"
            "resultScore" -> "score"
            "resultStatus" -> "status"
            "resultDetails" -> "details"
            "resultMetrics" -> "metrics"
            "resultRecommendations" -> "recommendations"
            "resultExecutionTimeMs" -> "execution_time_ms"
            "resultTimestamp" -> "timestamp"
            "resultError" -> "error"
            _ -> x
        }

data ProbeError = ProbeError
    { errorCode :: T.Text
    , errorMessage :: T.Text
    , errorDetails :: Maybe Value
    } deriving (Show, Generic)

instance ToJSON ProbeError where
    toJSON = genericToJSON defaultOptions
        { fieldLabelModifier = drop 5 }

-- Probe Interface
class Probe p where
    probeId :: p -> T.Text
    probeName :: p -> T.Text
    probeDescription :: p -> T.Text
    probeCategory :: p -> ProbeCategory
    probeVersion :: p -> T.Text
    
    execute :: p -> T.Text -> ProbeConfig -> IO ProbeResult
    validateConfig :: p -> ProbeConfig -> Either T.Text ()
    getRequirements :: p -> [T.Text]
    supportsBatch :: p -> Bool
    
    -- Default implementations
    getRequirements _ = []
    supportsBatch _ = False
    validateConfig _ config =
        if timeout config <= 0
            then Left "Timeout must be positive"
            else Right ()
```

### Bash Implementation

```bash
# Bash Probe Interface (functional approach)

# Probe metadata functions (each probe must implement these)
probe_id() {
    # Return unique probe identifier
    echo "unknown"
}

probe_name() {
    # Return human-readable name
    echo "Unknown Probe"
}

probe_description() {
    # Return detailed description
    echo "No description available"
}

probe_category() {
    # Return category: security|infrastructure|performance|compliance
    echo "security"
}

probe_version() {
    # Return probe version
    echo "1.0.0"
}

# Core probe functions (each probe must implement execute)
probe_execute() {
    local domain="$1"
    local config_file="$2"
    
    # Parse configuration
    local enabled
    local timeout
    enabled=$(probe_config_get "$config_file" "enabled" "true")
    timeout=$(probe_config_get "$config_file" "timeout" "30")
    
    # Validate configuration
    if ! probe_validate_config "$config_file"; then
        probe_result_error "invalid_config" "Configuration validation failed"
        return 1
    fi
    
    # Check if probe is enabled
    if [[ "$enabled" != "true" ]]; then
        probe_result_skip "Probe disabled in configuration"
        return 0
    fi
    
    # Execute probe logic (to be implemented by specific probes)
    probe_execute_impl "$domain" "$timeout"
}

probe_validate_config() {
    local config_file="$1"
    local timeout
    timeout=$(probe_config_get "$config_file" "timeout" "30")
    
    # Validate timeout is positive integer
    if ! [[ "$timeout" =~ ^[0-9]+$ ]] || [[ "$timeout" -le 0 ]]; then
        return 1
    fi
    
    return 0
}

probe_get_requirements() {
    # Return list of external dependencies (one per line)
    echo ""
}

probe_supports_batch() {
    # Return true if probe can handle multiple domains
    echo "false"
}

# Utility functions for probe results
probe_result_success() {
    local score="$1"
    local details="$2"
    shift 2
    local recommendations=("$@")
    
    probe_output_result "$(probe_id)" "$(probe_name)" "$(probe_category)" \
        "$score" "pass" "$details" "${recommendations[@]}"
}

probe_result_warning() {
    local score="$1"
    local details="$2"
    shift 2
    local recommendations=("$@")
    
    probe_output_result "$(probe_id)" "$(probe_name)" "$(probe_category)" \
        "$score" "warn" "$details" "${recommendations[@]}"
}

probe_result_failure() {
    local score="$1"
    local details="$2"
    shift 2
    local recommendations=("$@")
    
    probe_output_result "$(probe_id)" "$(probe_name)" "$(probe_category)" \
        "$score" "fail" "$details" "${recommendations[@]}"
}

probe_result_error() {
    local error_code="$1"
    local error_message="$2"
    
    probe_output_result "$(probe_id)" "$(probe_name)" "$(probe_category)" \
        "0" "error" "Error: $error_message" ""
}

# Configuration helpers
probe_config_get() {
    local config_file="$1"
    local key="$2"
    local default="$3"
    
    if [[ -f "$config_file" ]]; then
        # Simple YAML parser for basic key-value pairs
        grep "^${key}:" "$config_file" | cut -d':' -f2- | tr -d ' ' || echo "$default"
    else
        echo "$default"
    fi
}
```

## Probe Registration and Discovery

### Registry Interface

```typescript
interface ProbeRegistry {
    register(probe: Probe): void;
    unregister(probeId: string): void;
    get(probeId: string): Probe | null;
    list(): Probe[];
    listByCategory(category: ProbeCategory): Probe[];
    
    // Plugin support
    loadPlugin(path: string): void;
    loadPluginsFromDirectory(directory: string): void;
    
    // Validation
    validateAll(): ValidationResult[];
    checkDependencies(): DependencyResult[];
}
```

## Standard Probe Implementations

### TLS Probe Specification

```yaml
id: "tls"
name: "TLS Security Analysis"
description: "Comprehensive TLS/SSL security assessment"
category: "security"
version: "3.0.0"

configuration:
  timeout:
    type: "integer"
    default: 15
    description: "TLS connection timeout in seconds"
  
  min_tls_version:
    type: "string"
    enum: ["1.0", "1.1", "1.2", "1.3"]
    default: "1.2"
    description: "Minimum acceptable TLS version"
  
  comprehensive_analysis:
    type: "boolean"
    default: false
    description: "Enable SSL Labs-style comprehensive analysis"

output_metrics:
  - "protocol_version"
  - "cipher_suite"
  - "key_size"
  - "certificate_validity"
  - "certificate_chain_length"
  - "supported_protocols"
  - "vulnerability_status"

scoring_algorithm:
  protocol_version:
    "1.3": 100
    "1.2": 85
    "1.1": 60
    "1.0": 30
    "ssl3": 0
  
  key_size:
    ">=4096": 100
    ">=2048": 85
    ">=1024": 50
    "<1024": 0
  
  vulnerabilities:
    heartbleed: -80
    poodle: -60
    crime: -40
    beast: -30
```

### DNS Probe Specification

```yaml
id: "dns"
name: "DNS Security Analysis"
description: "DNS configuration and security assessment"
category: "infrastructure"
version: "3.0.0"

configuration:
  nameservers:
    type: "array"
    items:
      type: "string"
      format: "ipv4"
    default: ["8.8.8.8", "1.1.1.1"]
  
  check_dnssec:
    type: "boolean"
    default: true
  
  check_caa:
    type: "boolean"
    default: true

output_metrics:
  - "resolution_time"
  - "dnssec_status"
  - "caa_records"
  - "spf_records"
  - "dmarc_records"
  - "mx_records"
  - "ipv6_support"

scoring_algorithm:
  dnssec_enabled: +30
  caa_configured: +20
  spf_configured: +15
  dmarc_configured: +15
  ipv6_support: +10
  mx_records: +10
```

## Error Handling Standards

### Error Categories

```typescript
enum ProbeErrorCategory {
    CONFIGURATION = "configuration",
    NETWORK = "network", 
    TIMEOUT = "timeout",
    DEPENDENCY = "dependency",
    VALIDATION = "validation",
    INTERNAL = "internal"
}

interface StandardProbeError {
    category: ProbeErrorCategory;
    code: string;
    message: string;
    details?: any;
    recoverable: boolean;
    retry_after?: number; // seconds
}
```

### Standard Error Codes

```yaml
error_codes:
  configuration:
    - "INVALID_TIMEOUT"
    - "MISSING_REQUIRED_FIELD"
    - "INVALID_FORMAT"
  
  network:
    - "DNS_RESOLUTION_FAILED"
    - "CONNECTION_REFUSED"
    - "HOST_UNREACHABLE"
  
  timeout:
    - "CONNECT_TIMEOUT"
    - "READ_TIMEOUT"
    - "TOTAL_TIMEOUT"
  
  dependency:
    - "MISSING_BINARY"
    - "INCOMPATIBLE_VERSION"
    - "PERMISSION_DENIED"
  
  validation:
    - "INVALID_DOMAIN"
    - "MALFORMED_RESPONSE"
    - "UNEXPECTED_FORMAT"
  
  internal:
    - "MEMORY_ERROR"
    - "PROCESSING_ERROR"
    - "UNKNOWN_ERROR"
```

## Testing Standards

### Probe Unit Tests

Every probe implementation MUST include:

1. **Configuration Validation Tests**
   - Valid configuration acceptance
   - Invalid configuration rejection
   - Default value handling

2. **Execution Tests**
   - Successful execution with known-good domain
   - Error handling with unreachable domain
   - Timeout handling
   - Result format validation

3. **Scoring Tests**
   - Score calculation accuracy
   - Edge case handling
   - Boundary value testing

4. **Integration Tests**
   - Real domain testing
   - Cross-language result consistency
   - Performance benchmarking

### Test Domain Requirements

```yaml
test_domains:
  good_config:
    domain: "github.com"
    expected_score_range: [70, 90]
    expected_status: ["pass", "warn"]
  
  poor_config:
    domain: "badssl.com"
    expected_score_range: [0, 40]
    expected_status: ["fail", "warn"]
  
  timeout_test:
    domain: "httpbin.org/delay/30"
    timeout: 5
    expected_status: "error"
    expected_error_code: "CONNECT_TIMEOUT"
```

## Migration and Versioning

### Probe Version Compatibility

```yaml
compatibility_matrix:
  probe_version: "3.0.0"
  supported_engines:
    - engine: "python"
      min_version: "3.0.0"
      max_version: "3.x.x"
    - engine: "go"
      min_version: "3.0.0"
      max_version: "3.x.x"
    - engine: "rust"
      min_version: "3.0.0"
      max_version: "3.x.x"

migration_guide:
  from_version: "2.x.x"
  breaking_changes:
    - "Config field 'ssl_version' renamed to 'min_tls_version'"
    - "Result field 'score_details' moved to 'metrics'"
  
  migration_steps:
    - "Update configuration files"
    - "Modify result parsing logic"
    - "Run migration validation tests"
```

This standardized probe interface ensures that:

1. **Consistent Behavior**: All probes behave the same way across languages
2. **Easy Extension**: New probes can be added following the same pattern
3. **Type Safety**: Strong typing where supported by the language
4. **Error Handling**: Standardized error reporting and recovery
5. **Testing**: Comprehensive test requirements for reliability
6. **Maintenance**: Clear versioning and migration paths

The interface is designed to be language-idiomatic while maintaining functional equivalence across all implementations.