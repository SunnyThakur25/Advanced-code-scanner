#!/usr/bin/env python3
"""
Advanced Multi-Language Source Code Security Scanner with Parallel Processing
Author: Security Researcher
Description: Enterprise-grade security analysis with AST parsing, parallel processing, and advanced analysis
"""

import os
import re
import sys
import json
import argparse
import hashlib
import yaml
import ast
import subprocess
import requests
import time
import multiprocessing as mp
from pathlib import Path
from typing import List, Dict, Optional, Set, Any, Tuple, Union
from dataclasses import dataclass, asdict, field
from collections import defaultdict, Counter
import configparser
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import logging

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import toml
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False

try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False

try:
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class Issue:
    severity: str  # critical, high, medium, low
    category: str  # security, bug, code_quality, performance
    file_path: str
    line_number: int
    line_content: str
    description: str
    recommendation: str
    confidence: float = 1.0  # 0.0 to 1.0
    llm_analysis: Optional[str] = None
    pattern_match: Optional[str] = None
    ast_analysis: Optional[Dict] = None
    analyzer_type: str = "regex"  # regex, ast, taint, etc.

@dataclass
class ScanStatistics:
    total_files: int = 0
    total_lines: int = 0
    issues_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    issues_by_category: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    issues_by_language: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    top_files: List[Tuple[str, int]] = field(default_factory=list)
    scan_duration: float = 0.0
    llm_calls: int = 0
    cache_hits: int = 0
    parallel_workers: int = 0
    files_per_second: float = 0.0

class Configuration:
    """Enhanced Configuration management"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.patterns = self._get_default_patterns()
        self.exclusions = self._get_default_exclusions()
        self.llm_config = self._get_default_llm_config()
        self.scanning = self._get_default_scanning_config()
        
        if config_file:
            self._load_config(config_file)
    
    def _get_default_patterns(self) -> Dict:
        return {
            'global': {
                'critical': [
                    (r'password\s*=\s*["\'][^"\']{3,}', 'Hardcoded password found'),
                    (r'api[_-]?key\s*=\s*["\'][^"\']{10,}', 'Hardcoded API key found'),
                    (r'secret\s*=\s*["\'][^"\']{5,}', 'Hardcoded secret found'),
                    (r'token\s*=\s*["\'][^"\']{10,}', 'Hardcoded token found'),
                    (r'private[_-]?key\s*=\s*["\'][^"\']{20,}', 'Hardcoded private key found'),
                ],
                'high': [
                    (r'eval\s*\(', 'Use of eval() - potential code injection'),
                    (r'exec\s*\(', 'Use of exec() - potential code injection'),
                    (r'system\s*\(', 'Use of system() - potential command injection'),
                    (r'unsafe\s+redirect', 'Potential open redirect vulnerability'),
                ],
                'medium': [
                    (r'catch\s*\(\s*\w*\s*\)\s*\{\s*\}', 'Empty catch block - errors silently ignored'),
                    (r'except\s*:\s*pass', 'Empty except block - errors silently ignored'),
                    (r'ignore\s+errors', 'Error suppression - potential security issues'),
                ],
                'low': [
                    (r'TODO\s*:.*', 'Unresolved TODO comment'),
                    (r'FIXME\s*:.*', 'Unresolved FIXME comment'),
                    (r'print\s*\(', 'Debug print statement in production code'),
                ]
            },
            'per_language': {
                '.py': {
                    'critical': [
                        (r'pickle\.loads?\(', 'Unsafe deserialization - potential RCE'),
                        (r'yaml\.load\s*\(', 'Unsafe YAML loading - potential RCE'),
                    ],
                    'high': [
                        (r'input\s*\(', 'User input without validation'),
                    ]
                },
                '.js': {
                    'critical': [
                        (r'document\.write', 'Potential XSS vulnerability'),
                        (r'innerHTML\s*=', 'Potential XSS vulnerability'),
                    ],
                    'high': [
                        (r'setTimeout\s*\([^,]+,\s*\w+\s*\)', 'Potential XSS vulnerability'),
                    ]
                },
                '.go': {
                    'critical': [
                        (r'var\s+\w+\s*=\s*&\w+{}', 'Uninitialized struct with nil pointers'),
                    ],
                    'high': [
                        (r'fmt\.Print', 'Potential information disclosure'),
                    ]
                },
                '.java': {
                    'critical': [
                        (r'System\.exit', 'Hard exit - availability risk'),
                        (r'Runtime\.getRuntime\(\)\.exec', 'Command execution - potential RCE'),
                    ]
                },
                '.sql': {
                    'critical': [
                        (r'SELECT\s+\*\s+FROM.*WHERE.*=\s*["\']?\w+["\']?', 'Potential SQL injection'),
                    ]
                }
            }
        }
    
    def _get_default_exclusions(self) -> List[str]:
        return [
            '.git', 'node_modules', '__pycache__', '.venv', 'venv', 
            'build', 'dist', '.idea', '.vscode', '.pytest_cache',
            'target', '.gradle', 'bin', 'obj', '.sass-cache',
            '.next', '.nuxt', 'coverage', '.coverage'
        ]
    
    def _get_default_llm_config(self) -> Dict:
        return {
            'enabled': False,
            'model_type': 'local',
            'model_name': 'qwen2.5-coder:7b',
            'api_key': None,
            'base_url': 'http://localhost:11434',
            'cache_enabled': True,
            'cache_ttl': 3600,  # 1 hour
            'max_tokens': 500,
            'temperature': 0.3,
            'timeout': 60
        }
    
    def _get_default_scanning_config(self) -> Dict:
        return {
            'parallel': True,
            'max_workers': None,  # Use CPU count
            'chunk_size': 50,
            'use_threading': False,  # Process-based by default
            'timeout_per_file': 30,
            'severity_threshold': 'medium',  # Only report issues at this level or higher
            'sarif_output': False,
            'github_actions': False
        }
    
    def _load_config(self, config_file: str):
        """Load configuration from file"""
        config_path = Path(config_file)
        if not config_path.exists():
            logger.warning(f"Config file {config_file} not found")
            return
        
        try:
            if config_path.suffix.lower() in ['.yml', '.yaml']:
                with open(config_path, 'r') as f:
                    config_data = yaml.safe_load(f)
            elif config_path.suffix.lower() == '.json':
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
            elif config_path.suffix.lower() == '.toml' and TOML_AVAILABLE:
                with open(config_path, 'r') as f:
                    config_data = toml.load(f)
            else:
                # Try to parse as INI
                config = configparser.ConfigParser()
                config.read(config_path)
                config_data = {section: dict(config[section]) for section in config.sections()}
            
            # Merge with defaults
            if 'patterns' in config_data:
                self.patterns.update(config_data['patterns'])
            if 'exclusions' in config_data:
                self.exclusions = config_data['exclusions']
            if 'llm' in config_data:
                self.llm_config.update(config_data['llm'])
            if 'scanning' in config_data:
                self.scanning.update(config_data['scanning'])
                
        except Exception as e:
            logger.error(f"Failed to load config file {config_file}: {e}")

class LLMAnalyzer:
    """Enhanced LLM-based code analysis with caching and timeout"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.cache = {}
        self.cache_file = Path('.scanner_cache.json')
        self._load_cache()
        
        if config['model_type'] == "openai" and OPENAI_AVAILABLE:
            openai.api_key = config['api_key']
    
    def _load_cache(self):
        """Load cached LLM responses"""
        if self.config.get('cache_enabled', True) and self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                logger.info(f"Loaded {len(self.cache)} cached LLM responses")
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
                self.cache = {}
    
    def _save_cache(self):
        """Save cached LLM responses"""
        if self.config.get('cache_enabled', True):
            try:
                with open(self.cache_file, 'w') as f:
                    json.dump(self.cache, f, indent=2)
            except Exception as e:
                logger.warning(f"Failed to save cache: {e}")
    
    def _get_cache_key(self, prompt: str) -> str:
        """Generate cache key for prompt"""
        return hashlib.md5(prompt.encode()).hexdigest()
    
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached response is still valid"""
        if key not in self.cache:
            return False
        
        cache_entry = self.cache[key]
        ttl = self.config.get('cache_ttl', 3600)
        return (time.time() - cache_entry.get('timestamp', 0)) < ttl
    
    def analyze_code_issue(self, issue: Issue, code_context: str) -> str:
        """Use LLM to provide deeper analysis of code issues with caching and timeout"""
        
        prompt = f"""
        Analyze the following code security issue:

        File: {issue.file_path}:{issue.line_number}
        Code: {issue.line_content}
        Issue Type: {issue.category}
        Severity: {issue.severity}
        Description: {issue.description}

        Context:
        {code_context}

        Please provide:
        1. Detailed explanation of the security risk
        2. Potential attack scenarios
        3. Specific remediation steps
        4. Code example of secure implementation

        Keep response concise but informative.
        """
        
        # Check cache
        cache_key = self._get_cache_key(prompt)
        if self.config.get('cache_enabled', True) and self._is_cache_valid(cache_key):
            logger.info(f"Cache hit for issue in {issue.file_path}:{issue.line_number}")
            return self.cache[cache_key]['response']
        
        try:
            if self.config['model_type'] == "openai":
                response_text = self._analyze_with_openai(prompt)
            elif self.config['model_type'] == "local":
                response_text = self._analyze_with_local_llm(prompt)
            else:
                response_text = "LLM analysis not configured"
            
            # Cache the response
            if self.config.get('cache_enabled', True):
                self.cache[cache_key] = {
                    'response': response_text,
                    'timestamp': time.time(),
                    'prompt_hash': cache_key
                }
                self._save_cache()
            
            return response_text
            
        except Exception as e:
            return f"LLM analysis failed: {str(e)}"
    
    def _analyze_with_openai(self, prompt: str) -> str:
        """Analyze using OpenAI API with timeout"""
        if not OPENAI_AVAILABLE:
            return "OpenAI library not available"
            
        try:
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError("OpenAI API call timed out")
            
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.config.get('timeout', 60))
            
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self.config.get('max_tokens', 500),
                    temperature=self.config.get('temperature', 0.3)
                )
                return response.choices[0].message.content.strip()
            finally:
                signal.alarm(0)  # Cancel the alarm
                
        except TimeoutError:
            return "LLM analysis timed out"
        except Exception as e:
            return f"OpenAI analysis failed: {str(e)}"
    
    def _analyze_with_local_llm(self, prompt: str) -> str:
        """Analyze using local LLM via Ollama or similar with timeout"""
        try:
            model_name = self.config.get('model_name', 'qwen2.5-coder:7b')
            
            response = requests.post(
                f"{self.config['base_url']}/api/generate",
                json={
                    "model": model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.config.get('temperature', 0.3),
                        "max_tokens": self.config.get('max_tokens', 500)
                    }
                },
                timeout=self.config.get('timeout', 60)
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "No response from LLM")
            else:
                return f"Local LLM error: {response.status_code} - {response.text}"
                
        except requests.exceptions.Timeout:
            return "LLM analysis timed out"
        except requests.exceptions.RequestException as e:
            return f"Cannot connect to local LLM server: {str(e)}"
        except Exception as e:
            return f"Local LLM analysis failed: {str(e)}"

# AST Analyzers for different languages
class PythonASTAnalyzer:
    """Advanced Python AST-based analysis"""
    
    def __init__(self):
        self.issues = []
    
    def analyze_file(self, file_path: Path) -> List[Dict]:
        """Analyze Python file using AST"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                tree = ast.parse(content, filename=str(file_path))
            
            visitor = SecurityASTVisitor(file_path, content)
            visitor.visit(tree)
            issues.extend(visitor.issues)
        except SyntaxError as e:
            issues.append({
                'type': 'syntax_error',
                'message': f'Syntax error: {str(e)}',
                'line': getattr(e, 'lineno', 0),
                'severity': 'medium'
            })
        except Exception as e:
            logger.warning(f"AST parsing failed for {file_path}: {e}")
        
        return issues

class JavaScriptASTAnalyzer:
    """JavaScript AST-based analysis using Esprima"""
    
    def __init__(self):
        self.issues = []
    
    def analyze_file(self, file_path: Path) -> List[Dict]:
        """Analyze JavaScript file using Esprima"""
        issues = []
        if not ESPRIMA_AVAILABLE:
            return issues
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = esprima.parseScript(content, {'loc': True})
            issues.extend(self._analyze_tree(tree, content))
        except Exception as e:
            logger.warning(f"JavaScript AST parsing failed for {file_path}: {e}")
        
        return issues
    
    def _analyze_tree(self, tree, content: str) -> List[Dict]:
        """Analyze the parsed AST tree"""
        issues = []
        
        def visit(node):
            if hasattr(node, 'type'):
                if node.type == 'CallExpression':
                    if (hasattr(node, 'callee') and 
                        hasattr(node.callee, 'name') and 
                        node.callee.name in ['eval', 'document.write']):
                        issues.append({
                            'type': 'dangerous_function',
                            'message': f'Use of {node.callee.name}() - potential code injection',
                            'line': getattr(node, 'loc', {}).get('start', {}).get('line', 0),
                            'severity': 'high'
                        })
                elif node.type == 'AssignmentExpression':
                    if (hasattr(node, 'left') and 
                        hasattr(node.left, 'property') and 
                        getattr(node.left.property, 'name', '') == 'innerHTML'):
                        issues.append({
                            'type': 'xss_vulnerability',
                            'message': 'innerHTML assignment - potential XSS',
                            'line': getattr(node, 'loc', {}).get('start', {}).get('line', 0),
                            'severity': 'critical'
                        })
            
            # Recursively visit child nodes
            for key, value in vars(node).items():
                if isinstance(value, list):
                    for item in value:
                        if hasattr(item, 'type'):
                            visit(item)
                elif hasattr(value, 'type'):
                    visit(value)
        
        visit(tree)
        return issues

class SecurityASTVisitor(ast.NodeVisitor):
    """AST visitor for security analysis"""
    
    def __init__(self, file_path: Path, content: str):
        self.file_path = file_path
        self.content = content
        self.lines = content.split('\n')
        self.issues = []
        self.imports = set()
    
    def _get_line_content(self, lineno: int) -> str:
        """Get content of a specific line"""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""
    
    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module)
        self.generic_visit(node)
    
    def visit_Call(self, node):
        # Check for dangerous functions
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ['eval', 'exec', 'compile']:
                self.issues.append({
                    'type': 'dangerous_function',
                    'message': f'Use of {func_name}() - potential code injection',
                    'line': node.lineno,
                    'severity': 'high'
                })
            elif func_name == 'input':
                self.issues.append({
                    'type': 'user_input',
                    'message': 'User input without validation',
                    'line': node.lineno,
                    'severity': 'medium'
                })
        
        # Check for pickle usage
        elif isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name) and 
                node.func.value.id == 'pickle' and 
                node.func.attr in ['loads', 'load']):
                self.issues.append({
                    'type': 'unsafe_deserialization',
                    'message': 'Unsafe pickle deserialization - potential RCE',
                    'line': node.lineno,
                    'severity': 'critical'
                })
        
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        # Check for hardcoded secrets
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(keyword in var_name for keyword in ['password', 'secret', 'token', 'key']):
                    if isinstance(node.value, (ast.Constant, ast.Str)):
                        value = getattr(node.value, 'value', getattr(node.value, 's', ''))
                        if isinstance(value, str) and len(value) > 3:  # Likely a real secret
                            self.issues.append({
                                'type': 'hardcoded_secret',
                                'message': f'Hardcoded {var_name} found',
                                'line': node.lineno,
                                'severity': 'critical'
                            })
        self.generic_visit(node)

class TaintAnalyzer:
    """Basic taint analysis for data flow tracking"""
    
    def __init__(self):
        self.tainted_vars = set()
        self.sinks = ['eval', 'exec', 'system', 'os.system']
    
    def analyze_function(self, func_name: str, args: List[str]) -> List[Dict]:
        """Analyze if tainted data flows to dangerous functions"""
        issues = []
        
        # Check if any argument is tainted and function is dangerous
        if func_name in self.sinks:
            for arg in args:
                if arg in self.tainted_vars:
                    issues.append({
                        'type': 'taint_flow',
                        'message': f'Tainted data flows to {func_name}()',
                        'severity': 'critical'
                    })
        
        return issues

class CodeScanner:
    def __init__(self, config: Configuration):
        self.config = config
        self.issues: List[Issue] = []
        self.statistics = ScanStatistics()
        self.llm_analyzer = None
        
        if config.llm_config.get('enabled', False):
            self.llm_analyzer = LLMAnalyzer(config.llm_config)
        
        # Enhanced language support
        self.supported_extensions = {
            '.go', '.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.php', '.rb', 
            '.rs', '.swift', '.kt', '.scala', '.dart', '.lua', '.pl', '.sh', '.sql',
            '.html', '.xml', '.json', '.yml', '.yaml'
        }
        
        # Language-specific analyzers
        self.language_analyzers = {
            '.py': PythonASTAnalyzer(),
            '.js': JavaScriptASTAnalyzer() if ESPRIMA_AVAILABLE else None
        }
        
        # Enhanced patterns
        self.security_patterns = self._build_patterns()
        
        # Set up parallel processing
        max_workers = config.scanning.get('max_workers')
        if max_workers is None:
            max_workers = min(32, (mp.cpu_count() or 1) + 4)
        self.max_workers = max_workers

    def _build_patterns(self) -> Dict:
        """Build comprehensive security patterns"""
        patterns = self.config.patterns.get('global', {})
        
        # Add more language-specific patterns
        additional_patterns = {
            # C/C++ patterns
            'cpp_critical': [
                (r'sprintf\s*\(', 'Potential buffer overflow'),
                (r'gets\s*\(', 'Dangerous function - buffer overflow'),
                (r'strcpy\s*\(', 'Potential buffer overflow'),
            ],
            
            # PHP patterns
            'php_critical': [
                (r'eval\s*\(', 'Use of eval() - potential code injection'),
                (r'mysql_query\s*\(', 'Deprecated MySQL function - potential SQL injection'),
            ],
            
            # Shell patterns
            'sh_critical': [
                (r'eval\s+', 'Use of eval - potential command injection'),
                (r'\$\([^)]+\)', 'Command substitution - potential injection'),
            ],
            
            # Configuration file patterns
            'config_critical': [
                (r'"password"\s*:\s*"[^"]{3,}"', 'Hardcoded password in config'),
                (r'"api[_-]?key"\s*:\s*"[^"]{10,}"', 'Hardcoded API key in config'),
            ]
        }
        
        # Merge with existing patterns
        for category, pattern_list in additional_patterns.items():
            if category not in patterns:
                patterns[category] = []
            patterns[category].extend(pattern_list)
        
        return patterns

    def get_code_context(self, file_path: Path, line_number: int, context_lines: int = 5) -> str:
        """Get surrounding code context for better analysis"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            context = []
            for i in range(start, end):
                line_num = i + 1
                prefix = ">>> " if line_num == line_number else "    "
                context.append(f"{prefix}{line_num:4d}: {lines[i].rstrip()}")
            
            return "\n".join(context)
        except Exception:
            return "Context unavailable"

    def _should_report_issue(self, severity: str) -> bool:
        """Check if issue should be reported based on severity threshold"""
        severity_order = ['low', 'medium', 'high', 'critical']
        threshold = self.config.scanning.get('severity_threshold', 'medium')
        
        try:
            issue_index = severity_order.index(severity)
            threshold_index = severity_order.index(threshold)
            return issue_index >= threshold_index
        except ValueError:
            return True  # If we can't determine, report it

    def scan_file(self, file_path: Path) -> List[Issue]:
        """Scan a single file for issues"""
        issues = []
        file_extension = file_path.suffix.lower()
        
        # Update statistics
        self.statistics.total_files += 1
        self.statistics.issues_by_language[file_extension] += 1
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                self.statistics.total_lines += len(lines)
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return issues
        
        # AST-based analysis for supported languages
        if file_extension in self.language_analyzers and self.language_analyzers[file_extension]:
            ast_analyzer = self.language_analyzers[file_extension]
            ast_issues = ast_analyzer.analyze_file(file_path)
            for ast_issue in ast_issues:
                severity = ast_issue.get('severity', 'medium')
                if not self._should_report_issue(severity):
                    continue
                    
                line_num = ast_issue.get('line', 0)
                line_content = self._get_line_content(file_path, line_num) if line_num > 0 else ""
                
                issues.append(Issue(
                    severity=severity,
                    category='ast_analysis',
                    file_path=str(file_path),
                    line_number=line_num,
                    line_content=line_content,
                    description=ast_issue.get('message', 'AST analysis issue'),
                    recommendation='Review the AST analysis findings',
                    ast_analysis=ast_issue,
                    confidence=0.9,
                    analyzer_type='ast'
                ))
        
        # Regex-based pattern matching
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
                
            # Check global patterns
            for category, patterns in self.security_patterns.items():
                for pattern, description in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        severity = self._get_severity_from_category(category)
                        if not self._should_report_issue(severity):
                            continue
                            
                        issue = Issue(
                            severity=severity,
                            category='regex_pattern',
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line[:150],
                            description=description,
                            recommendation=self._get_recommendation(description),
                            confidence=self._get_confidence(category, description),
                            pattern_match=pattern,
                            analyzer_type='regex'
                        )
                        
                        # Add LLM analysis if enabled
                        if self.llm_analyzer:
                            context = self.get_code_context(file_path, line_num)
                            issue.llm_analysis = self.llm_analyzer.analyze_code_issue(issue, context)
                            self.statistics.llm_calls += 1
                        
                        issues.append(issue)
            
            # Check language-specific patterns
            if file_extension in self.config.patterns.get('per_language', {}):
                lang_patterns = self.config.patterns['per_language'][file_extension]
                for category, patterns in lang_patterns.items():
                    for pattern, description in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            severity = self._get_severity_from_category(category)
                            if not self._should_report_issue(severity):
                                continue
                                
                            issue = Issue(
                                severity=severity,
                                category='language_specific',
                                file_path=str(file_path),
                                line_number=line_num,
                                line_content=line[:150],
                                description=description,
                                recommendation=self._get_recommendation(description),
                                confidence=self._get_confidence(category, description),
                                pattern_match=pattern,
                                analyzer_type='regex'
                            )
                            
                            # Add LLM analysis if enabled
                            if self.llm_analyzer:
                                context = self.get_code_context(file_path, line_num)
                                issue.llm_analysis = self.llm_analyzer.analyze_code_issue(issue, context)
                                self.statistics.llm_calls += 1
                            
                            issues.append(issue)
        
        # Update statistics
        for issue in issues:
            self.statistics.issues_by_severity[issue.severity] += 1
            self.statistics.issues_by_category[issue.category] += 1
        
        return issues

    def _get_line_content(self, file_path: Path, line_number: int) -> str:
        """Get content of a specific line from file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                if 1 <= line_number <= len(lines):
                    return lines[line_number - 1].strip()[:150]
        except Exception:
            pass
        return ""

    def _get_severity_from_category(self, category: str) -> str:
        """Extract severity from category name"""
        if 'critical' in category:
            return 'critical'
        elif 'high' in category:
            return 'high'
        elif 'medium' in category:
            return 'medium'
        elif 'low' in category:
            return 'low'
        else:
            return 'medium'

    def _get_confidence(self, category: str, description: str) -> float:
        """Calculate confidence based on pattern type"""
        if 'critical' in category:
            return 0.95
        elif 'high' in category:
            return 0.85
        elif 'medium' in category:
            return 0.7
        else:
            return 0.5

    def _get_recommendation(self, description: str) -> str:
        """Provide recommendations based on issue description"""
        recommendations = {
            'Hardcoded': 'Use environment variables, secure configuration management, or secret management systems',
            'eval()': 'Avoid dangerous functions or properly sanitize and validate all inputs',
            'exec()': 'Avoid dangerous functions or properly sanitize and validate all inputs',
            'system()': 'Use safer alternatives or properly sanitize command arguments',
            'XSS': 'Sanitize and escape user input, use Content Security Policy',
            'SQL injection': 'Use parameterized queries or ORM frameworks',
            'buffer overflow': 'Use safer string functions, validate input lengths',
            'RCE': 'Avoid dynamic code execution, validate and sanitize inputs',
            'SSRF': 'Validate URLs, use allowlists for allowed domains',
            'TODO': 'Address the TODO or create proper issue tracking',
            'FIXME': 'Address the FIXME or create proper issue tracking',
            'debug': 'Remove debug code from production builds',
            'empty catch': 'Implement proper error handling and logging',
            'ignored error': 'Handle all error return values appropriately'
        }
        
        for key, recommendation in recommendations.items():
            if key in description:
                return recommendation
        
        return 'Review and address this issue following security best practices'

    def _scan_file_wrapper(self, file_path_str: str) -> List[Issue]:
        """Wrapper for parallel processing"""
        file_path = Path(file_path_str)
        try:
            return self.scan_file(file_path)
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return []

    def scan_directory(self, directory_path: str, exclude_dirs: List[str] = None) -> List[Issue]:
        """Scan entire directory recursively with parallel processing"""
        if exclude_dirs is None:
            exclude_dirs = self.config.exclusions
            
        issues = []
        path = Path(directory_path)
        
        if not path.exists():
            logger.error(f"Directory {directory_path} does not exist")
            return issues
            
        logger.info(f"Scanning directory: {directory_path}")
        
        # Find all files to scan
        files_to_scan = []
        for file_path in path.rglob('*'):
            # Skip excluded directories
            if any(exclude_dir in str(file_path) for exclude_dir in exclude_dirs):
                continue
                
            # Check if it's a supported file type
            if file_path.is_file() and file_path.suffix.lower() in self.supported_extensions:
                files_to_scan.append(str(file_path))
        
        logger.info(f"Found {len(files_to_scan)} files to scan")
        
        start_time = time.time()
        scanned_files = 0
        
        # Parallel scanning
        if self.config.scanning.get('parallel', True) and len(files_to_scan) > 1:
            use_threading = self.config.scanning.get('use_threading', False)
            chunk_size = self.config.scanning.get('chunk_size', 50)
            
            executor_class = ThreadPoolExecutor if use_threading else ProcessPoolExecutor
            logger.info(f"Using {'threading' if use_threading else 'multiprocessing'} with {self.max_workers} workers")
            
            with executor_class(max_workers=self.max_workers) as executor:
                # Submit all files
                future_to_file = {
                    executor.submit(self._scan_file_wrapper, file_path): file_path 
                    for file_path in files_to_scan
                }
                
                # Collect results
                for future in future_to_file:
                    try:
                        file_issues = future.result(timeout=self.config.scanning.get('timeout_per_file', 30))
                        issues.extend(file_issues)
                        scanned_files += 1
                        
                        # Update top files statistics
                        if file_issues:
                            file_path = future_to_file[future]
                            self.statistics.top_files.append((file_path, len(file_issues)))
                            
                    except Exception as e:
                        file_path = future_to_file[future]
                        logger.error(f"Error scanning {file_path}: {e}")
        else:
            # Sequential scanning
            logger.info("Using sequential scanning")
            for file_path_str in files_to_scan:
                file_issues = self._scan_file_wrapper(file_path_str)
                issues.extend(file_issues)
                scanned_files += 1
                
                # Update top files statistics
                if file_issues:
                    self.statistics.top_files.append((file_path_str, len(file_issues)))
        
        # Sort top files by issue count
        self.statistics.top_files.sort(key=lambda x: x[1], reverse=True)
        self.statistics.top_files = self.statistics.top_files[:10]  # Top 10
        
        self.statistics.scan_duration = time.time() - start_time
        self.statistics.parallel_workers = self.max_workers
        self.statistics.files_per_second = scanned_files / self.statistics.scan_duration if self.statistics.scan_duration > 0 else 0
        
        logger.info(f"Scanned {scanned_files} files in {self.statistics.scan_duration:.2f} seconds")
        logger.info(f"Performance: {self.statistics.files_per_second:.1f} files/second")
        
        return issues

    def generate_statistics_report(self) -> str:
        """Generate statistical analysis of scan results"""
        stats = self.statistics
        report = []
        
        report.append("=" * 60)
        report.append("SCAN STATISTICS REPORT")
        report.append("=" * 60)
        report.append(f"Total Files Scanned: {stats.total_files}")
        report.append(f"Total Lines Analyzed: {stats.total_lines:,}")
        report.append(f"Scan Duration: {stats.scan_duration:.2f} seconds")
        report.append(f"Files per Second: {stats.files_per_second:.1f}")
        report.append(f"Parallel Workers: {stats.parallel_workers}")
        report.append("")
        
        # Issues by severity
        report.append("ISSUES BY SEVERITY:")
        report.append("-" * 30)
        severity_order = ['critical', 'high', 'medium', 'low']
        for severity in severity_order:
            count = stats.issues_by_severity.get(severity, 0)
            if count > 0:
                percentage = (count / len(self.issues) * 100) if self.issues else 0
                report.append(f"  {severity.upper()}: {count} ({percentage:.1f}%)")
        report.append("")
        
        # Issues by category
        report.append("ISSUES BY CATEGORY:")
        report.append("-" * 30)
        sorted_categories = sorted(stats.issues_by_category.items(), key=lambda x: x[1], reverse=True)
        for category, count in sorted_categories:
            report.append(f"  {category}: {count}")
        report.append("")
        
        # Issues by language
        report.append("ISSUES BY LANGUAGE:")
        report.append("-" * 30)
        sorted_languages = sorted(stats.issues_by_language.items(), key=lambda x: x[1], reverse=True)
        for language, count in sorted_languages:
            report.append(f"  {language}: {count}")
        report.append("")
        
        # Top problematic files
        if stats.top_files:
            report.append("TOP 10 FILES WITH MOST ISSUES:")
            report.append("-" * 40)
            for file_path, count in stats.top_files:
                report.append(f"  {file_path}: {count} issues")
        
        # LLM statistics
        if self.llm_analyzer:
            report.append("")
            report.append("LLM ANALYSIS STATISTICS:")
            report.append("-" * 30)
            report.append(f"  LLM Calls: {stats.llm_calls}")
            report.append(f"  Cache Hits: {stats.cache_hits}")
            if stats.llm_calls > 0:
                cache_hit_rate = (stats.cache_hits / stats.llm_calls) * 100
                report.append(f"  Cache Hit Rate: {cache_hit_rate:.1f}%")
        
        return "\n".join(report)

    def generate_sarif_report(self, issues: List[Issue]) -> Dict:
        """Generate SARIF format report for CI/CD integration"""
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Advanced Code Scanner",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/security-researcher/code-scanner"
                    }
                },
                "results": []
            }]
        }
        
        results = []
        for issue in issues:
            result = {
                "ruleId": f"{issue.category}-{issue.severity}",
                "ruleIndex": 0,
                "level": self._sarif_level(issue.severity),
                "message": {
                    "text": issue.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": issue.file_path
                        },
                        "region": {
                            "startLine": issue.line_number,
                            "snippet": {
                                "text": issue.line_content
                            }
                        }
                    }
                }],
                "properties": {
                    "confidence": issue.confidence,
                    "recommendation": issue.recommendation
                }
            }
            
            if issue.llm_analysis:
                result["properties"]["llmAnalysis"] = issue.llm_analysis
                
            results.append(result)
        
        sarif_report["runs"][0]["results"] = results
        return sarif_report

    def _sarif_level(self, severity: str) -> str:
        """Map severity to SARIF level"""
        level_map = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note'
        }
        return level_map.get(severity, 'warning')

    def generate_github_actions_report(self, issues: List[Issue]) -> str:
        """Generate GitHub Actions annotations"""
        annotations = []
        
        for issue in issues:
            if issue.severity in ['critical', 'high']:
                annotation_type = "error"
            elif issue.severity == 'medium':
                annotation_type = "warning"
            else:
                annotation_type = "notice"
                
            annotation = f"::{annotation_type} file={issue.file_path},line={issue.line_number}::{issue.description}"
            annotations.append(annotation)
        
        return "\n".join(annotations)

    def generate_report(self, issues: List[Issue], output_format: str = 'text') -> str:
        """Generate report in specified format"""
        if output_format == 'json':
            return self._generate_json_report(issues)
        elif output_format == 'detailed':
            return self._generate_detailed_report(issues)
        elif output_format == 'sarif':
            sarif_data = self.generate_sarif_report(issues)
            return json.dumps(sarif_data, indent=2)
        elif output_format == 'github':
            return self.generate_github_actions_report(issues)
        else:
            return self._generate_text_report(issues)

    def _generate_text_report(self, issues: List[Issue]) -> str:
        """Generate human-readable text report"""
        if not issues:
            return "No issues found! 🎉"
            
        # Group by severity
        severity_groups = defaultdict(list)
        for issue in issues:
            severity_groups[issue.severity].append(issue)
            
        report = []
        report.append("=" * 80)
        report.append("SOURCE CODE SECURITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Total Issues Found: {len(issues)}")
        if self.llm_analyzer:
            report.append("LLM Analysis: Enabled")
        report.append("")
        
        # Summary by severity
        severity_order = ['critical', 'high', 'medium', 'low']
        severity_counts = {severity: len(issues_list) for severity, issues_list in severity_groups.items()}
        
        report.append("ISSUE SUMMARY:")
        report.append("-" * 40)
        for severity in severity_order:
            count = severity_counts.get(severity, 0)
            if count > 0:
                report.append(f"  {severity.upper()}: {count}")
        report.append("")
        
        # Detailed issues
        for severity in severity_order:
            if severity in severity_groups:
                issues_list = severity_groups[severity]
                report.append(f"{severity.upper()} ISSUES ({len(issues_list)}):")
                report.append("=" * 60)
                
                for i, issue in enumerate(issues_list, 1):
                    report.append(f"[{i}] {issue.description}")
                    report.append(f"    File: {issue.file_path}:{issue.line_number}")
                    report.append(f"    Code: {issue.line_content}")
                    report.append(f"    Confidence: {issue.confidence:.1%}")
                    report.append(f"    Recommendation: {issue.recommendation}")
                    report.append(f"    Analyzer: {issue.analyzer_type}")
                    
                    if issue.llm_analysis:
                        report.append(f"    LLM Analysis:")
                        for line in issue.llm_analysis.split('\n'):
                            report.append(f"      {line}")
                    report.append("")
                    
        return "\n".join(report)

    def _generate_detailed_report(self, issues: List[Issue]) -> str:
        """Generate detailed report with statistics"""
        main_report = self._generate_text_report(issues)
        stats_report = self.generate_statistics_report()
        
        return f"{main_report}\n\n{stats_report}"

    def _generate_json_report(self, issues: List[Issue]) -> str:
        """Generate JSON report"""
        issues_dict = []
        for issue in issues:
            issue_dict = asdict(issue)
            issues_dict.append(issue_dict)
            
        report_data = {
            'scan_info': {
                'total_issues': len(issues),
                'llm_enabled': self.llm_analyzer is not None,
                'statistics': asdict(self.statistics)
            },
            'issues': issues_dict
        }
        
        return json.dumps(report_data, indent=2)

    def save_report(self, issues: List[Issue], output_file: str, format: str = 'text'):
        """Save report to file"""
        if format == 'sarif':
            sarif_data = self.generate_sarif_report(issues)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(sarif_data, f, indent=2)
        else:
            report_content = self.generate_report(issues, format)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
        logger.info(f"Report saved to {output_file}")

def create_sample_config():
    """Create sample configuration file"""
    sample_config = {
        'patterns': {
            'global': {
                'critical': [
                    ['password\\s*=\\s*["\'][^"\']{3,}', 'Hardcoded password found'],
                    ['api[_-]?key\\s*=\\s*["\'][^"\']{10,}', 'Hardcoded API key found']
                ],
                'high': [
                    ['eval\\s*\\(', 'Use of eval() - potential code injection']
                ]
            },
            'per_language': {
                '.py': {
                    'critical': [
                        ['pickle\\.loads?\\(', 'Unsafe deserialization - potential RCE']
                    ]
                },
                '.js': {
                    'critical': [
                        ['document\\.write', 'Potential XSS vulnerability']
                    ]
                }
            }
        },
        'exclusions': [
            '.git', 'node_modules', '__pycache__', '.venv', 'venv'
        ],
        'llm': {
            'enabled': True,
            'model_type': 'local',
            'model_name': 'qwen2.5-coder:7b',
            'base_url': 'http://localhost:11434',
            'cache_enabled': True,
            'cache_ttl': 3600
        },
        'scanning': {
            'parallel': True,
            'max_workers': None,
            'use_threading': False,
            'severity_threshold': 'medium',
            'sarif_output': True
        }
    }
    
    with open('scanner_config.yaml', 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False)
    
    logger.info("Sample configuration file created: scanner_config.yaml")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Multi-Language Source Code Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 advanced_scanner.py /path/to/code/
  
  # Scan with configuration file
  python3 advanced_scanner.py /path/to/code/ --config scanner_config.yaml
  
  # Scan with statistical analysis
  python3 advanced_scanner.py /path/to/code/ --format detailed
  
  # Generate SARIF report for CI/CD
  python3 advanced_scanner.py /path/to/code/ --format sarif -o results.sarif
  
  # Create sample configuration
  python3 advanced_scanner.py --create-config
  
  # Scan with local LLM analysis
  python3 advanced_scanner.py /path/to/code/ --config scanner_config.yaml
        """
    )
    
    parser.add_argument('path', nargs='?', help='File or directory to scan')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'detailed', 'sarif', 'github'], 
                       default='text', help='Report format')
    parser.add_argument('-e', '--exclude', nargs='*', help='Directories to exclude')
    parser.add_argument('-c', '--config', help='Configuration file (YAML/JSON/TOML)')
    parser.add_argument('--create-config', action='store_true', help='Create sample configuration file')
    parser.add_argument('--list-languages', action='store_true', help='List supported languages')
    parser.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'], 
                       help='Minimum severity threshold')
    
    args = parser.parse_args()
    
    if args.create_config:
        create_sample_config()
        return
    
    if args.list_languages:
        print("Supported Languages:")
        print("- Go (.go)")
        print("- Python (.py)")
        print("- JavaScript (.js)")
        print("- TypeScript (.ts)")
        print("- Java (.java)")
        print("- C++ (.cpp, .cc)")
        print("- C (.c)")
        print("- C# (.cs)")
        print("- PHP (.php)")
        print("- Ruby (.rb)")
        print("- Rust (.rs)")
        print("- Swift (.swift)")
        print("- Kotlin (.kt)")
        print("- Scala (.scala)")
        print("- Dart (.dart)")
        print("- Lua (.lua)")
        print("- Perl (.pl)")
        print("- Shell (.sh)")
        print("- SQL (.sql)")
        print("- HTML (.html)")
        print("- XML (.xml)")
        print("- JSON (.json)")
        print("- YAML (.yml, .yaml)")
        return
    
    if not args.path:
        parser.print_help()
        return
    
    # Load configuration
    config = Configuration(args.config)
    
    # Override exclusions if provided
    if args.exclude:
        config.exclusions = args.exclude
    
    # Override severity threshold if provided
    if args.severity:
        config.scanning['severity_threshold'] = args.severity
    
    # Initialize scanner
    scanner = CodeScanner(config)
    
    # Determine if it's a file or directory
    path = Path(args.path)
    if path.is_file():
        issues = scanner.scan_file(path)
    elif path.is_dir():
        issues = scanner.scan_directory(str(path))
    else:
        logger.error(f"Error: {args.path} is not a valid file or directory")
        sys.exit(1)
    
    # Store issues for reporting
    scanner.issues = issues
    
    # Generate and display report
    report = scanner.generate_report(issues, args.format)
    print(report)
    
    # Save to file if specified
    if args.output:
        scanner.save_report(issues, args.output, args.format)

if __name__ == '__main__':
    main()
