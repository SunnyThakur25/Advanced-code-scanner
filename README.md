Advanced Code Security Scanner 

   
   

    

A comprehensive, multi-language source code security scanner with AI-powered analysis capabilities. 

This tool identifies security vulnerabilities, code quality issues, and potential risks in source code using both traditional pattern matching and advanced LLM-assisted analysis. 
# 🌟 Key Features 
🔍 Multi-Language Security Analysis 

    18+ Programming Languages: Python, JavaScript, Java, Go, C/C++, C#, PHP, Ruby, Rust, Swift, Kotlin, Scala, Dart, Lua, Perl, Shell, SQL, HTML/XML
    AST-Based Analysis: Deep semantic analysis for Python and JavaScript
    Language-Specific Patterns: Custom security rules for each language
     

🤖 AI-Powered Security Insights 

    Local LLM Integration: Works with Qwen, CodeLlama, DeepSeek Coder, and other local models
    Cloud LLM Support: OpenAI GPT integration for advanced analysis
    Intelligent Caching: Reduces costs and improves performance
    Context-Aware Analysis: Considers code context for better insights
     

⚡ High-Performance Scanning 

    Parallel Processing: Multi-core scanning for large codebases
    Configurable Workers: Adjustable parallel processing settings
    Performance Metrics: Real-time scanning statistics
    Timeout Protection: Prevents hanging on large files
     

🛠️ Professional Integration 

    SARIF Output: Industry-standard security report format
    GitHub Actions: Native CI/CD pipeline integration
    Multiple Output Formats: Text, JSON, detailed reports
    Severity Filtering: Focus on critical issues
     

# 🚀 Quick Start 
Installation 
# Clone the repository
```
git clone https://github.com/SunnyThakur25/Advanced-code-scanner.git
cd advanced-code-scanner

# Install dependencies
pip install -r requirements.txt

# Optional: Install additional dependencies for enhanced features
pip install openai esprima lxml toml
```

# Basic Usage
```
# Scan a single file
python3 advanced_scanner.py /path/to/file.py

# Scan a directory
python3 advanced_scanner.py /path/to/project/

# Scan with AI analysis (requires local LLM setup)
python3 advanced_scanner.py /path/to/project/ --config config.yaml
```
# 🛠️ Setup and Configuration 
Local LLM Setup (Recommended) 

    Install Ollama: 
    
    # Linux/Mac
    
`curl -fsSL https://ollama.com/install.sh | sh`

# Windows: Download from https://ollama.com/download

# Pull AI Models:
```
# Qwen 2.5 Coder (Recommended)
ollama pull qwen2.5-coder:7b

# Alternative models
ollama pull codellama
ollama pull deepseek-coder
ollama pull codegemma

```

# Start Ollama Server:
`ollama serve`

# Configuration File 
```
Create a scanner_config.yaml file: 
patterns:
  global:
    critical:
      - - 'password\s*=\s*["\'][^"\']{3,}'
        - 'Hardcoded password found'
      - - 'api[_-]?key\s*=\s*["\'][^"\']{10,}'
        - 'Hardcoded API key found'

  per_language:
    .py:
      critical:
        - - 'pickle\.loads?\('
          - 'Unsafe deserialization - potential RCE'

exclusions:
  - '.git'
  - 'node_modules'
  - '__pycache__'
  - '.venv'

llm:
  enabled: true
  model_type: 'local'
  model_name: 'qwen2.5-coder:7b'
  base_url: 'http://localhost:11434'
  cache_enabled: true

scanning:
  parallel: true
  severity_threshold: 'medium'
```

Generate a sample configuration:
`python3 advanced_scanner.py --create-config`

# 📖 Usage Examples 
Basic Security Scanning 
```
# Simple directory scan
python3 advanced_scanner.py /path/to/project/

# Scan with custom configuration
python3 advanced_scanner.py /path/to/project/ --config my_config.yaml

# Exclude specific directories
python3 advanced_scanner.py /path/to/project/ --exclude build dist node_modules

# Focus on critical issues only
python3 advanced_scanner.py /path/to/project/ --severity critical

```

# Advanced AI Analysis
# Enable local LLM analysis
`python3 advanced_scanner.py /path/to/project/ --config ai_config.yaml`

# Use OpenAI for analysis
```
python3 advanced_scanner.py /path/to/project/ \
  --config openai_config.yaml \
  --llm-model openai \
  --api-key your-openai-key
```

# CI/CD Integration
```
# Generate SARIF report for GitHub Actions
python3 advanced_scanner.py /path/to/project/ \
  --format sarif \
  -o security-results.sarif

# GitHub Actions output
python3 advanced_scanner.py /path/to/project/ \
  --format github \
  --severity high
```
# Performance Optimization
```
# High-performance scanning
python3 advanced_scanner.py /path/to/large-project/ \
  --config performance_config.yaml

# Custom worker settings
python3 advanced_scanner.py /path/to/project/ \
  --workers 16 \
  --chunk-size 100
```

# 📊 Output Formats 
Text Report 
`python3 advanced_scanner.py /path/to/project/ --format text`

Detailed Report with Statistics
`python3 advanced_scanner.py /path/to/project/ --format detailed -o report.txt`

JSON Output
`python3 advanced_scanner.py /path/to/project/ --format json -o results.json`
SARIF for CI/CD
`python3 advanced_scanner.py /path/to/project/ --format sarif -o results.sarif`


# 🔧 Advanced Configuration 
Performance Tuning
```
scanning:
  parallel: true
  max_workers: 16          # Number of parallel workers
  use_threading: false     # Use processes instead of threads
  chunk_size: 50           # Files per worker chunk
  timeout_per_file: 30     # Timeout per file in seconds
  severity_threshold: 'high'  # Minimum severity to report
```
LLM Settings
```
llm:
  enabled: true
  model_type: 'local'      # local or openai
  model_name: 'qwen2.5-coder:7b'
  base_url: 'http://localhost:11434'
  cache_enabled: true      # Cache LLM responses
  cache_ttl: 3600          # Cache timeout (1 hour)
  max_tokens: 500          # Max tokens per response
  temperature: 0.3         # Response creativity
  timeout: 60              # LLM API timeout
```
Language-Specific Patterns
patterns:
```
  per_language:
    .py:
      critical:
        - - 'eval\s*\('
          - 'Use of eval() - potential code injection'
      high:
        - - 'input\s*\('
          - 'User input without validation'
    
    .js:
      critical:
        - - 'document\.write'
          - 'Potential XSS vulnerability'
```
# 🔒 Security Features 
Detected Vulnerability Types 

    Hardcoded Secrets: Passwords, API keys, tokens
    Injection Attacks: SQL injection, command injection, XSS
    Unsafe Functions: eval(), exec(), system()
    Deserialization Issues: Unsafe pickle, YAML loading
    Buffer Overflows: Unsafe C/C++ functions
    Error Handling: Empty catch blocks, ignored errors
    Code Quality: TODO/FIXME comments, debug code
     

AI-Powered Analysis 

    Risk Assessment: Detailed security risk explanations
    Attack Scenarios: Potential exploitation methods
    Remediation Steps: Specific code fixes
    Secure Examples: Better implementation patterns
     

# 🤝 Integration Examples 
GitHub Actions Workflow 
```
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    - name: Run security scan
      run: |
        python3 advanced_scanner.py . --format github --severity high
```
🎯 Professional Use Cases 
Security Audits 
# Comprehensive security audit
```
python3 advanced_scanner.py /path/to/client-project/ \
  --format detailed \
  -o security-audit-$(date +%Y%m%d).pdf \
  --config audit_config.yaml
```
Continuous Security Monitoring
# Regular automated scans
```python3 advanced_scanner.py /path/to/project/ \
  --severity high \
  --format json \
  -o /var/log/security-scans/scan-$(date +%Y%m%d-%H%M%S).json
```
  Compliance Checking
  # OWASP Top 10 compliance
```python3 advanced_scanner.py /path/to/project/ \
  --config owasp_config.yaml \
  --format detailed
```

📋 Requirements 
Minimum Requirements 

    Python 3.7+
    2GB RAM minimum
    1 CPU core
     

Recommended for Large Projects 

    Python 3.8+
    8GB+ RAM
    4+ CPU cores
    Local LLM server (Ollama recommended)
     

# Optional Dependencies 
```
# For OpenAI integration
pip install openai

# For JavaScript AST analysis
pip install esprima

# For XML/HTML parsing
pip install lxml

# For TOML configuration files
pip install toml
```
🛡️ Best Practices 
1. Regular Scanning
 ```
2. # Daily security scans
0 2 * * * cd /path/to/project && python3 advanced_scanner.py . --severity high
```
2. Pre-commit Hooks
   # .pre-commit-config.yaml
```repos:
  - repo: local
    hooks:
      - id: security-scan
        name: Security Scan
        entry: python3 /path/to/advanced_scanner.py
        language: python
        files: \.(py|js|java|go)$
```
3. CI/CD Integration 

Always integrate security scanning into your development pipeline: 

    Run on every pull request
    Block merges for critical issues
    Generate reports for security teams
     

🆘 Troubleshooting 
Common Issues 

    LLM Connection Errors 

    # Ensure Ollama is running
`ollama serve`

# Check if model is available
`ollama list`

Permission Errors

# Run with appropriate permissions
`sudo python3 advanced_scanner.py /path/to/project/`

Memory Issues
# Reduce parallel workers
`python3 advanced_scanner.py /path/to/project/ --workers 4`

Performance Tuning 
```
For large codebases: 
# Use threading for I/O bound operations
python3 advanced_scanner.py /path/to/large-project/ --use-threading

# Adjust chunk size
python3 advanced_scanner.py /path/to/project/ --chunk-size 25

```
📚 Documentation 
Command Line Options 
`python3 advanced_scanner.py --help`

🤝 Contributing 
Development Setup 
```
# Clone and setup
git clone https://github.com/SunnyThakur25/Advanced-code-scanner.git
cd advanced-code-scanner
pip install -e .

# Run tests
python3 -m pytest tests/
```


Adding New Language Support 

    Create a new AST analyzer class
    Add language patterns to configuration
    Update supported extensions list
    Add tests for the new language
     

Extending Analysis Capabilities 

    Add new pattern categories
    Implement additional AST visitors
    Create custom analyzers
    Enhance LLM prompts
     

📄 License 

This project is licensed under the Apache License 2.0 - see the LICENSE  file for details. 
🙏 Acknowledgments 

    Thanks to the Ollama team for excellent local LLM support
    Inspired by industry-standard security tools
    Built with security research community input
     

📞 Support 

For issues, questions, or contributions: 

    Open a GitHub issue
    Contact the security research team
    

 

# Note: This tool is designed for security professionals and developers to improve code quality and security. Always ensure you have proper authorization before scanning any codebase. 
 

