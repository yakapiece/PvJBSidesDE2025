# 🤖 Local LLMs for PvJ Team Members

*Offline AI assistance for log analysis, command generation, and troubleshooting during competition*

---

## 🎯 Why Local LLMs for PvJ?

### Competition Advantages
- **No internet dependency** - Works during network issues or restrictions
- **Instant response** - No API rate limits or latency
- **Privacy** - Sensitive logs and commands stay local
- **Customization** - Can be fine-tuned for cybersecurity tasks
- **Cost-effective** - No per-query costs during long competitions

### PvJ-Specific Use Cases
- **Log analysis** - Parse and explain complex log entries
- **Command generation** - Generate platform-specific commands
- **Error troubleshooting** - Diagnose system and service issues
- **Configuration assistance** - Help with config file syntax
- **Documentation lookup** - Quick reference for tools and procedures

---

## 💻 Hardware Requirements by Category

### Lightweight (8-16GB RAM)
- **Good for**: Command assistance, basic log analysis
- **Models**: 3B-7B parameters
- **Response time**: 1-5 seconds
- **Use case**: Quick queries during active competition

### Medium (16-32GB RAM)
- **Good for**: Complex log analysis, detailed troubleshooting
- **Models**: 7B-13B parameters  
- **Response time**: 2-10 seconds
- **Use case**: In-depth analysis during investigation phases

### Heavy (32GB+ RAM)
- **Good for**: Advanced analysis, code generation, complex reasoning
- **Models**: 13B-70B parameters
- **Response time**: 5-30 seconds
- **Use case**: Deep analysis during preparation or post-incident review

---

## 🚀 Recommended Local LLM Solutions

### 1. **Ollama** (Easiest Setup)
```bash
# Installation
curl -fsSL https://ollama.ai/install.sh | sh

# Popular models for cybersecurity
ollama pull llama3.1:8b          # General purpose, good balance
ollama pull codellama:7b         # Code and command generation
ollama pull mistral:7b           # Fast, efficient
ollama pull llama3.1:70b         # Most capable (requires 64GB+ RAM)

# Usage examples
ollama run llama3.1:8b "Explain this Apache error log: [ERROR] [pid 1234] Permission denied"
ollama run codellama:7b "Generate a PowerShell command to check for failed login attempts"
```

**Pros**: Simple setup, model management, REST API
**Cons**: Limited customization options
**Best for**: Quick deployment, general use

### 2. **LM Studio** (User-Friendly GUI)
- **Download**: https://lmstudio.ai/
- **Platform**: Windows, macOS, Linux
- **Features**: GUI interface, model browser, chat interface

```bash
# Recommended models in LM Studio
- microsoft/DialoGPT-medium (lightweight, conversational)
- TheBloke/Llama-2-7B-Chat-GGML (balanced performance)
- TheBloke/CodeLlama-7B-Instruct-GGUF (code assistance)
- TheBloke/Mistral-7B-Instruct-v0.1-GGUF (fast responses)
```

**Pros**: Easy GUI, no command line needed, model discovery
**Cons**: Less automation-friendly
**Best for**: Team members uncomfortable with command line

### 3. **GPT4All** (Privacy-Focused)
```bash
# Installation
pip install gpt4all

# Python usage
from gpt4all import GPT4All
model = GPT4All("mistral-7b-openorca.Q4_0.gguf")
response = model.generate("Analyze this SSH log entry: Failed password for root from 192.168.1.100")
```

**Pros**: Strong privacy focus, Python integration, offline-first
**Cons**: Limited model selection
**Best for**: Privacy-conscious teams, Python integration

### 4. **Llamafile** (Single Executable)
```bash
# Download and run (example with TinyLlama)
wget https://huggingface.co/jartine/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/TinyLlama-1.1B-Chat-v1.0.Q5_K_M.llamafile
chmod +x TinyLlama-1.1B-Chat-v1.0.Q5_K_M.llamafile
./TinyLlama-1.1B-Chat-v1.0.Q5_K_M.llamafile

# Access via browser at http://localhost:8080
```

**Pros**: Single file, no dependencies, web interface
**Cons**: Limited to specific model builds
**Best for**: Portable deployment, minimal setup

### 5. **Text Generation WebUI** (Advanced)
```bash
# Installation
git clone https://github.com/oobabooga/text-generation-webui
cd text-generation-webui
./start_linux.sh  # or start_windows.bat

# Supports many model formats: GGUF, GPTQ, AWQ, EXL2
```

**Pros**: Extensive model support, advanced features, extensions
**Cons**: Complex setup, resource intensive
**Best for**: Advanced users, custom fine-tuning

---

## 🛡️ Cybersecurity-Optimized Models

### General Purpose (Recommended)
1. **Llama 3.1 8B Instruct**
   - **Size**: ~5GB
   - **RAM**: 8-12GB
   - **Strengths**: Excellent reasoning, good with technical content
   - **Use**: General troubleshooting, log analysis

2. **Mistral 7B Instruct**
   - **Size**: ~4GB  
   - **RAM**: 6-10GB
   - **Strengths**: Fast responses, good instruction following
   - **Use**: Quick command generation, basic analysis

3. **CodeLlama 7B Instruct**
   - **Size**: ~4GB
   - **RAM**: 6-10GB
   - **Strengths**: Code and command generation
   - **Use**: Script writing, configuration files

### Specialized Models
4. **Phind CodeLlama 34B**
   - **Size**: ~20GB
   - **RAM**: 24-32GB
   - **Strengths**: Advanced code analysis, debugging
   - **Use**: Complex troubleshooting, system analysis

5. **WizardCoder 15B**
   - **Size**: ~9GB
   - **RAM**: 12-16GB
   - **Strengths**: Code generation and explanation
   - **Use**: Script creation, configuration assistance

6. **Dolphin 2.6 Mixtral 8x7B**
   - **Size**: ~26GB
   - **RAM**: 32GB+
   - **Strengths**: Uncensored, technical discussions
   - **Use**: Advanced analysis, unrestricted assistance

---

## 🔧 Setup Instructions by Platform

### Windows Setup (Ollama)
```powershell
# Install Ollama
winget install Ollama.Ollama

# Pull recommended models
ollama pull llama3.1:8b
ollama pull codellama:7b
ollama pull mistral:7b

# Test installation
ollama run llama3.1:8b "Hello, can you help with Windows event log analysis?"
```

### Linux Setup (Ollama)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull models
ollama pull llama3.1:8b
ollama pull codellama:7b
ollama pull mistral:7b

# Start as service
sudo systemctl enable ollama
sudo systemctl start ollama

# Test
ollama run llama3.1:8b "Help me analyze this Linux auth.log entry"
```

### macOS Setup (LM Studio)
```bash
# Download LM Studio from https://lmstudio.ai/
# Install and launch
# Browse and download models through GUI
# Recommended: Llama-2-7B-Chat, CodeLlama-7B-Instruct
```

---

## 🎯 PvJ-Specific Prompts and Use Cases

### Log Analysis Prompts
```
"Analyze this Apache error log and suggest troubleshooting steps: [LOG_ENTRY]"

"Explain what this Windows Event ID means and potential causes: [EVENT_DETAILS]"

"Parse this SSH auth.log entry and identify security concerns: [LOG_LINE]"

"Interpret this DNS query log and flag suspicious patterns: [DNS_LOG]"
```

### Command Generation Prompts
```
"Generate a PowerShell command to check for failed login attempts in the last hour"

"Create a Linux command to find files modified in the last 30 minutes in /var/log"

"Write an iptables rule to log traffic on port 443 without blocking it"

"Generate a BIND zone file entry for hostname [NAME] with IP [IP]"
```

### Troubleshooting Prompts
```
"Service [SERVICE] won't start on [OS]. Walk me through troubleshooting steps."

"DNS resolution is failing. Provide a systematic diagnostic approach."

"Web server returning 500 errors. What should I check first?"

"Database connection timeout errors. List potential causes and fixes."
```

### Configuration Assistance
```
"Review this Apache virtual host configuration for security issues: [CONFIG]"

"Explain each line of this iptables ruleset: [RULES]"

"Optimize this MySQL configuration for performance: [CONFIG]"

"Validate this BIND zone file syntax: [ZONE_FILE]"
```

---

## 🚀 Quick Start Guide for Competition Day

### Pre-Competition Setup (1 hour)
1. **Install Ollama** on team laptops
2. **Download models**: `ollama pull llama3.1:8b codellama:7b mistral:7b`
3. **Test functionality** with sample queries
4. **Create prompt templates** for common tasks
5. **Verify offline operation** (disconnect internet and test)

### Competition Day Usage
```bash
# Quick command assistance
ollama run codellama:7b "Generate command to restart Apache on Ubuntu"

# Log analysis
ollama run llama3.1:8b "Analyze: $(tail -1 /var/log/auth.log)"

# Troubleshooting
ollama run mistral:7b "DNS service won't start, named-checkconf shows no errors. Next steps?"

# Configuration help
ollama run llama3.1:8b "Explain this iptables rule: iptables -A INPUT -p tcp --dport 22 -j LOG"
```

### Integration with Team Workflow
```bash
# Create helper scripts
cat > /tmp/llm_helper.sh << 'EOF'
#!/bin/bash
case $1 in
    "log") ollama run llama3.1:8b "Analyze this log entry: $2" ;;
    "cmd") ollama run codellama:7b "Generate command: $2" ;;
    "debug") ollama run mistral:7b "Troubleshoot: $2" ;;
    *) echo "Usage: llm_helper.sh [log|cmd|debug] 'your query'" ;;
esac
EOF

chmod +x /tmp/llm_helper.sh

# Usage examples
./llm_helper.sh log "Failed password for root from 192.168.1.100"
./llm_helper.sh cmd "check for listening ports on Linux"
./llm_helper.sh debug "Apache won't start after config change"
```

---

## 📊 Performance Comparison

| Model | Size | RAM Req | Speed | Quality | Best Use |
|-------|------|---------|-------|---------|----------|
| TinyLlama 1B | 1GB | 2-4GB | Very Fast | Basic | Quick queries |
| Mistral 7B | 4GB | 6-10GB | Fast | Good | General use |
| Llama3.1 8B | 5GB | 8-12GB | Medium | Excellent | Analysis |
| CodeLlama 7B | 4GB | 6-10GB | Fast | Good | Commands |
| Llama3.1 70B | 40GB | 64GB+ | Slow | Excellent | Complex tasks |

---

## 🔒 Security and Privacy Considerations

### Data Privacy
- **All processing local** - No data sent to external servers
- **No internet required** - Works in isolated environments
- **Sensitive logs safe** - Queries don't leave your machine
- **No usage tracking** - Complete privacy

### Security Best Practices
```bash
# Restrict model access
chmod 600 ~/.ollama/models/*

# Run in isolated environment
docker run -it --rm -v ollama:/root/.ollama -p 11434:11434 ollama/ollama

# Monitor resource usage
htop  # Watch CPU/RAM usage during model inference

# Clean up sensitive queries
history -c  # Clear command history after competition
```

### Competition Environment
- **Test offline functionality** before competition
- **Verify model performance** under stress
- **Prepare fallback options** if primary model fails
- **Document usage procedures** for team members

---

## 🛠️ Advanced Configuration

### Custom Model Fine-Tuning (Pre-Competition)
```bash
# Create cybersecurity-specific training data
cat > cybersec_training.jsonl << 'EOF'
{"prompt": "Analyze this log:", "completion": "This Apache error indicates..."}
{"prompt": "Generate iptables rule:", "completion": "iptables -A INPUT..."}
EOF

# Fine-tune with Ollama (requires technical expertise)
ollama create cybersec-assistant -f Modelfile
```

### API Integration for Team Tools
```python
# Python integration example
import requests
import json

def query_local_llm(prompt):
    response = requests.post('http://localhost:11434/api/generate',
                           json={'model': 'llama3.1:8b', 'prompt': prompt})
    return response.json()['response']

# Usage in team scripts
log_analysis = query_local_llm(f"Analyze this log: {log_entry}")
```

### Resource Optimization
```bash
# Optimize for competition environment
export OLLAMA_NUM_PARALLEL=1  # Limit parallel requests
export OLLAMA_MAX_LOADED_MODELS=1  # Conserve memory
export OLLAMA_FLASH_ATTENTION=1  # Enable optimizations
```

---

## 📋 Team Deployment Checklist

### Pre-Competition (1 week before)
- [ ] Install LLM software on all team laptops
- [ ] Download and test recommended models
- [ ] Create team-specific prompt templates
- [ ] Test offline functionality
- [ ] Train team members on basic usage
- [ ] Prepare helper scripts and aliases

### Competition Day Setup (30 minutes)
- [ ] Verify LLM services are running
- [ ] Test model responsiveness
- [ ] Load competition-specific prompts
- [ ] Confirm offline operation
- [ ] Brief team on usage protocols

### During Competition
- [ ] Use for log analysis and troubleshooting
- [ ] Generate commands and configurations
- [ ] Assist with documentation and reporting
- [ ] Support decision-making under pressure

---

## 💡 Pro Tips for Competition Use

### Efficiency Tips
- **Prepare common prompts** in advance
- **Use aliases** for frequent queries
- **Keep models warm** with periodic queries
- **Batch similar questions** to save time

### Quality Tips
- **Be specific** in your prompts
- **Provide context** about your environment
- **Ask for step-by-step** explanations
- **Request multiple options** when troubleshooting

### Team Coordination
- **Designate LLM operators** to avoid conflicts
- **Share useful prompts** with team members
- **Document successful queries** for reuse
- **Use for training** newer team members

---

*Local LLMs provide a significant competitive advantage by offering instant, private, and reliable AI assistance throughout the competition. Proper setup and team training can dramatically improve troubleshooting speed and decision quality.*

**Remember: The best LLM is the one your team knows how to use effectively under pressure.**

