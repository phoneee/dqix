# DQIX Unified CLI

This directory contains the **unified CLI implementation** that replaces multiple separate scripts with a single, maintainable interface.

## ⚠️ Architecture Change

**BEFORE** (Bloated): 6 separate scripts with ~4000 lines of duplicated code
- `dqix` (1178 lines)
- `dqix-multi` (1037 lines) 
- `dqix-educational` (436 lines)
- `dqix-parallel` (507 lines)
- `dqix-performance` (208 lines)
- `dqix-complete.sh` (633 lines)

**AFTER** (Clean): Unified architecture with ~300 lines, zero duplication
- `dqix-unified` - Single CLI with mode flags
- `lib/core.sh` - Shared assessment functions  
- `lib/output.sh` - Unified output formatting

## 🚀 Usage

### Standard Assessment
```bash
./dqix-unified scan example.com
```

### Educational Mode (with explanations)
```bash
./dqix-unified scan example.com --educational
```

### Performance Mode (quick scan)
```bash
./dqix-unified scan example.com --performance
```

### Parallel Mode (batch processing)
```bash
./dqix-unified scan example.com --parallel
```

### Comprehensive Mode (SSL Labs style)
```bash
./dqix-unified scan example.com --comprehensive
```

### JSON Output
```bash
./dqix-unified scan example.com --json
./dqix-unified scan example.com --comprehensive --json
```

### Quiet/Verbose Modes
```bash
./dqix-unified scan example.com --quiet
./dqix-unified scan example.com --verbose
```

## 📁 Architecture

```
dqix-cli/
├── dqix-unified*           # Main CLI entry point
├── lib/                    # Shared libraries
│   ├── core.sh*           # Assessment and scoring functions
│   └── output.sh*         # Output formatting functions
└── README.md              # This file

# Legacy files (to be removed):
├── dqix*                  # Legacy unified script
├── dqix-multi*            # Legacy multi-mode script  
├── dqix-educational*      # Legacy educational script
├── dqix-parallel*         # Legacy parallel script
├── dqix-performance*      # Legacy performance script
└── dqix-complete.sh*      # Legacy completion script
```

## 🎯 Benefits

### Code Quality
- **93% reduction** in code duplication
- **Single point of maintenance**
- **Consistent behavior** across all modes
- **Modular architecture** with separation of concerns

### User Experience  
- **Unified interface** - one command to learn
- **Mode flags** instead of separate scripts
- **Consistent options** across all modes
- **Better help** and error messages

### Developer Experience
- **Easier testing** - single codebase to validate
- **Simpler maintenance** - fix once, works everywhere
- **Clear architecture** - functions organized by purpose
- **Better documentation** - single source of truth

## 🔄 Migration Guide

| Old Command | New Command |
|-------------|-------------|
| `./dqix scan example.com` | `./dqix-unified scan example.com` |
| `./dqix-educational scan example.com` | `./dqix-unified scan example.com --educational` |
| `./dqix-parallel scan example.com` | `./dqix-unified scan example.com --parallel` |
| `./dqix-performance scan example.com` | `./dqix-unified scan example.com --performance` |

## 🧪 Testing

Test all modes to ensure functionality:

```bash
# Test standard mode
./dqix-unified scan example.com

# Test educational mode
./dqix-unified scan example.com --educational

# Test JSON output
./dqix-unified scan example.com --json

# Test error handling
./dqix-unified scan invalid-domain
./dqix-unified help
```

## 📋 Features

✅ **TLS/SSL Security Assessment**  
✅ **DNS Security Evaluation**  
✅ **HTTPS Configuration Analysis**  
✅ **Security Headers Validation**  
✅ **Multiple Output Formats** (Pretty, JSON)  
✅ **Educational Mode** (with explanations)  
✅ **Performance Mode** (optimized for speed)  
✅ **Comprehensive Mode** (detailed analysis)  
✅ **Cross-language Compatibility**  
✅ **Unified Interface**  

## 🔧 Development

To extend functionality:

1. **Add new probe**: Modify `lib/core.sh`
2. **Add new output format**: Modify `lib/output.sh`  
3. **Add new mode**: Modify `dqix-unified` argument parsing
4. **Add new option**: Update both parsing and libraries

This architecture ensures changes propagate consistently across all modes.

---

**This unified CLI maintains full feature parity while eliminating technical debt and improving maintainability.**