# 💻 PvJ Laptop Specifications Guide

*Minimum and recommended specs for BSides Pros vs. Joes competition across all platforms*

---

## 🎯 PvJ Technical Requirements Overview

### What Your Laptop Needs to Handle
- **8+ hours of continuous use** (competition duration)
- **Multiple SSH sessions** (connecting to various servers)
- **Web browsing** (scorebot monitoring, documentation)
- **Text editing** (configuration files, documentation)
- **Network monitoring tools** (Wireshark, basic packet analysis)
- **Log analysis** (viewing large text files, basic parsing)
- **Team communication** (Discord, Slack, video calls)
- **Screen sharing** (team coordination)

### Performance Considerations
- **Multitasking**: Multiple terminals, browser tabs, communication apps
- **Network connectivity**: Reliable WiFi and ethernet capability
- **Battery life**: Power outlets may be limited
- **Screen real estate**: Multiple windows and terminal sessions
- **Keyboard comfort**: Extensive typing and command entry

---

## 🪟 Windows Laptops

### Minimum Specifications
- **CPU**: Intel Core i5-8th gen or AMD Ryzen 5 3000 series
- **RAM**: 8GB DDR4 (16GB strongly recommended)
- **Storage**: 256GB SSD (500GB recommended)
- **Display**: 13" 1080p minimum (15" preferred for screen real estate)
- **Battery**: 6+ hours rated (8+ hours preferred)
- **Ports**: USB-A, USB-C, HDMI, Ethernet (or USB-C adapter)
- **WiFi**: 802.11ac (WiFi 6 preferred)
- **OS**: Windows 10/11 Pro (for better networking features)

### Recommended Models (Budget-Friendly)
- **Lenovo ThinkPad E15** (~$600-800)
  - Excellent keyboard, good build quality
  - Strong Linux compatibility if dual-booting
- **ASUS VivoBook 15** (~$500-700)
  - Good value, decent performance
  - Lightweight for portability
- **Acer Aspire 5** (~$400-600)
  - Budget option, adequate performance
  - Upgradeable RAM/storage

### Premium Options
- **Lenovo ThinkPad T14/T15** (~$1000-1500)
  - Professional grade, excellent keyboard
  - Superior build quality and reliability
- **Dell Latitude 5000 series** (~$800-1200)
  - Business-grade reliability
  - Good port selection

---

## 🐧 Linux Laptops

### Minimum Specifications
- **CPU**: Intel Core i5-8th gen or AMD Ryzen 5 3000 series
- **RAM**: 8GB DDR4 (16GB recommended for VMs)
- **Storage**: 256GB SSD (500GB recommended)
- **Display**: 13" 1080p minimum (15" preferred)
- **Battery**: 6+ hours rated (8+ hours preferred)
- **Ports**: USB-A, USB-C, HDMI, Ethernet
- **WiFi**: 802.11ac with good Linux driver support
- **Graphics**: Intel integrated or AMD (avoid NVIDIA for Linux compatibility)

### Linux-Friendly Models
- **System76 Galago Pro** (~$1000-1400)
  - Pre-installed Pop!_OS
  - Excellent Linux hardware support
- **Lenovo ThinkPad X1 Carbon** (~$1200-1800)
  - Premium build, excellent Linux compatibility
  - Great keyboard and trackpad
- **Dell XPS 13 Developer Edition** (~$1000-1500)
  - Ships with Ubuntu
  - High-quality display and build

### Budget Linux Options
- **Lenovo ThinkPad T480/T490** (refurbished ~$400-600)
  - Excellent Linux support
  - Upgradeable, reliable
- **ASUS ZenBook 14** (~$600-800)
  - Good Linux compatibility
  - Lightweight and portable

### Distribution Recommendations for PvJ
- **Ubuntu 22.04 LTS** - Best hardware support, stable
- **Pop!_OS** - Gaming-focused, excellent hardware detection
- **Fedora** - Cutting-edge, good for developers
- **Debian** - Rock-solid stability, minimal bloat

---

## 🍎 Mac Laptops

### Minimum Specifications
- **Model**: MacBook Air M1/M2 or MacBook Pro 13" (2020+)
- **CPU**: Apple M1 or Intel Core i5-10th gen minimum
- **RAM**: 8GB unified memory (16GB strongly recommended)
- **Storage**: 256GB SSD (512GB recommended)
- **Display**: 13" Retina minimum (external monitor helpful)
- **Battery**: 8+ hours (Macs generally excel here)
- **Ports**: USB-C/Thunderbolt (dongles required for ethernet)
- **OS**: macOS Monterey or newer

### Recommended Models
- **MacBook Air M2** (~$1200-1500)
  - Excellent performance and battery life
  - Fanless design (quiet in competition environment)
  - Great for SSH, terminal work, web browsing
- **MacBook Pro 13" M2** (~$1300-1600)
  - Better sustained performance
  - Active cooling for intensive tasks
- **MacBook Pro 14" M1 Pro** (~$2000+)
  - Premium option with excellent screen real estate
  - Multiple external display support

### Mac-Specific Considerations
- **Terminal**: Built-in Terminal.app is excellent for SSH
- **Package management**: Install Homebrew for additional tools
- **Networking tools**: Some Linux tools may need alternatives
- **Dongles required**: USB-C to Ethernet adapter essential
- **VM support**: Parallels/VMware for Windows/Linux VMs if needed

---

## 🔧 Essential Software Requirements

### Cross-Platform Must-Haves
- **SSH Client**: Built-in (Linux/Mac) or PuTTY/Windows Terminal (Windows)
- **Text Editor**: VS Code, Sublime Text, or vim/nano
- **Web Browser**: Chrome/Firefox with good tab management
- **Terminal Emulator**: Built-in or Windows Terminal/iTerm2
- **Network Tools**: Wireshark, nmap (where permitted)
- **Communication**: Discord, Slack, Zoom/Teams

### Platform-Specific Tools

#### Windows
- **Windows Subsystem for Linux (WSL2)** - Linux tools on Windows
- **PuTTY** or **Windows Terminal** - SSH connectivity
- **Notepad++** - Advanced text editing
- **PowerShell 7** - Modern shell environment

#### Linux
- **Package manager tools** - apt, yum, pacman (distribution-specific)
- **tmux/screen** - Terminal multiplexing
- **htop** - System monitoring
- **tcpdump** - Network packet capture

#### macOS
- **Homebrew** - Package management
- **iTerm2** - Enhanced terminal
- **Spectacle/Rectangle** - Window management
- **Network tools** via Homebrew

---

## 💰 Budget Recommendations by Price Range

### Under $500
- **Refurbished ThinkPad T480** (Linux) - ~$400
- **Acer Aspire 5** (Windows) - ~$450
- **Used MacBook Air 2018** - ~$500

### $500-$1000
- **Lenovo ThinkPad E15** (Windows/Linux) - ~$700
- **ASUS VivoBook 15** (Windows) - ~$600
- **System76 Galago Pro** (Linux) - ~$1000

### $1000-$1500
- **MacBook Air M2** - ~$1200
- **Lenovo ThinkPad T14** - ~$1200
- **Dell XPS 13** - ~$1100

### $1500+
- **MacBook Pro 14"** - ~$2000
- **Lenovo ThinkPad X1 Carbon** - ~$1600
- **System76 Oryx Pro** - ~$1800

---

## 🔋 Battery Life Considerations

### PvJ-Specific Battery Needs
- **Competition duration**: 8+ hours
- **Power outlet availability**: Limited and contested
- **Performance vs. battery**: Balance needed

### Battery Life by Platform
- **Mac**: Generally 8-12 hours (M1/M2 chips excel)
- **Windows**: 6-10 hours (varies significantly by model)
- **Linux**: 5-9 hours (depends on power management setup)

### Battery Optimization Tips
- **Lower screen brightness** during competition
- **Close unnecessary applications**
- **Use power-saving modes** when not under heavy load
- **Bring portable charger** as backup
- **Consider external battery pack** for extended use

---

## 🌐 Network Connectivity Requirements

### Essential Connectivity
- **Ethernet port** or USB-C/USB-A adapter
- **Stable drivers** for your OS
- **VPN compatibility** if team uses VPN

### Adapter Requirements
- **USB-C to Ethernet** (especially for Macs)
- **USB-A to Ethernet** (backup option)
- **USB hub** for additional ports if needed

---

## 🎯 Performance Benchmarks for PvJ Tasks

### Minimum Performance Targets
- **SSH session startup**: <2 seconds
- **Large log file opening**: <5 seconds for 100MB file
- **Web browser with 20+ tabs**: Smooth operation
- **Wireshark packet capture**: Real-time analysis capability
- **Multiple terminal windows**: 10+ without lag

### Memory Usage Expectations
- **Base OS**: 2-4GB RAM
- **Web browser**: 2-4GB RAM (with multiple tabs)
- **SSH sessions**: 50-100MB per session
- **Text editors**: 100-500MB
- **Communication apps**: 200-500MB
- **Buffer for tools**: 2-4GB recommended

---

## 🛠️ Hardware Reliability Factors

### Build Quality Priorities
1. **Keyboard durability** - Extensive typing during competition
2. **Hinge reliability** - Frequent opening/closing
3. **Port durability** - Multiple cable connections
4. **Thermal management** - 8+ hours of continuous use
5. **WiFi antenna quality** - Stable network connectivity

### Brands Known for Reliability
- **Business-grade**: Lenovo ThinkPad, Dell Latitude
- **Consumer reliable**: ASUS, Acer (mid-range and up)
- **Premium**: Apple MacBook, System76
- **Avoid**: Ultra-budget models, gaming laptops (overkill + poor battery)

---

## 📋 Pre-Event Hardware Checklist

### 30 Days Before Event
- [ ] Purchase/acquire laptop meeting minimum specs
- [ ] Install and configure required software
- [ ] Test SSH connectivity and network tools
- [ ] Verify battery life under realistic workload
- [ ] Order necessary adapters and accessories

### 1 Week Before Event
- [ ] Update all software and drivers
- [ ] Test all tools and applications
- [ ] Verify team communication software works
- [ ] Charge laptop and test battery life
- [ ] Pack necessary adapters and cables

### Day of Event
- [ ] Arrive with fully charged laptop
- [ ] Test network connectivity immediately
- [ ] Verify all tools are working
- [ ] Set up team communication
- [ ] Configure power management for long session

---

## 💡 Pro Tips from Veterans

### Hardware Lessons Learned
- **"Bring ethernet adapter"** - WiFi can be unreliable with many participants
- **"Test everything beforehand"** - No time to troubleshoot hardware during competition
- **"Comfortable keyboard matters"** - You'll be typing for 8+ hours
- **"Screen size affects productivity"** - Bigger is better for multitasking
- **"Battery life is critical"** - Power outlets are limited and contested

### Platform-Specific Advice
- **Windows**: Enable WSL2 for Linux tools
- **Linux**: Test hardware compatibility thoroughly
- **Mac**: Invest in quality USB-C hub with ethernet
- **All platforms**: Practice with your exact setup beforehand

---

*Remember: The best laptop for PvJ is the one you're comfortable with and know how to use effectively. Don't buy new hardware right before the event - use what you know and test everything thoroughly.*

**Focus on reliability, battery life, and your comfort with the platform over raw performance specs.**

