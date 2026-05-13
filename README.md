# SmartPatch: AI-Driven Security Mitigation for Legacy Windows

**SmartPatch** is an intelligent vulnerability assessment and mitigation recommendation system designed for legacy Windows environments (Windows 7, Server 2008, and beyond). It combines semantic search (RAG), machine learning-based risk prioritization, and complete explainability to provide SOC analysts with actionable, trustworthy security recommendations.

## 🎯 Core Problem

Legacy Windows systems (XP, 7, Server 2008) are:
- ❌ Not supported by modern security tools (Wazuh, SCCM require latest Windows)
- ❌ Still running in hospitals, factories, banks, government agencies
- ❌ Under-resourced with small IT teams that can't afford downtime
- ❌ Air-gapped or offline (no cloud connectivity)

**SmartPatch is purpose-built for this gap.**

## ✨ What Makes SmartPatch Different

| Feature | SmartPatch | Wazuh | SCCM | Qualys |
|---------|-----------|-------|------|--------|
| **Legacy Windows (XP/7)** | ✅ | ❌ | ❌ | ❌ |
| **Offline-First** | ✅ | ❌ | ❌ | ❌ |
| **AI Prioritization** | ✅ | ❌ | ❌ | ❌ |
| **Explainability** | ✅ | ⚠️ | ⚠️ | ⚠️ |
| **No Cloud Dependency** | ✅ | ❌ | ⚠️ | ❌ |
| **Simple Deployment** | ✅ | ⚠️ | ❌ | ❌ |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│         Web Dashboard (html5up-spectral)                    │
│         - Vulnerability overview                            │
│         - AI recommendations with priority                  │
│         - Implementation guides & scripts                   │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│         Flask REST API (port 8888)                          │
│         - /api/scan-summary                                 │
│         - /api/vulnerabilities                              │
│         - /api/recommendations (AI-powered)                 │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│      SmartPatch Orchestration Pipeline                      │
│ ┌──────────────┬──────────────┬──────────────┐              │
│ │   Scanner    │   RAG Engine │ Recommender  │              │
│ │ (Windows)    │ (Semantic)   │ (Mapping)    │              │
│ └──────────────┴──────────────┴──────────────┘              │
│                                                              │
│ ┌──────────────┬──────────────────────────────┐              │
│ │ Prioritizer  │    Explainability Engine      │              │
│ │ (Risk/Effort)│ (Audit Trail + Confidence)   │              │
│ └──────────────┴──────────────────────────────┘              │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│         Data Layer                                           │
│ ┌──────────────┬──────────────┬──────────────┐              │
│ │  dev_db.sqlite  │ EPSS Scores  │ KEV Data   │              │
│ │ (5315 CVEs)  │ (Risk)       │ (Exploited) │              │
│ └──────────────┴──────────────┴──────────────┘              │
│ ┌────────────────────────────────────────────┐              │
│ │  FAISS Index (Semantic Search Vectors)     │              │
│ └────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Install Dependencies
```powershell
cd SmartPatch
pip install -r requirements.txt
```

### 2. Run SmartPatch
```powershell
powershell -ExecutionPolicy Bypass -File start-smartpatch.ps1
```

That's it! The launcher will:
- Start the backend API (port 8888)
- Verify all systems are operational
- Open the dashboard in your browser

### 3. Run First Assessment
1. Navigate to **"Security Scanner"** in the dashboard
2. Click **"Run Assessment"**
3. Wait for scan to complete (1-2 minutes)
4. View **"Mitigation Plan"** for AI-prioritized recommendations

## 📊 Key Features

### Complete Pipeline
```
Windows System Data → RAG Search → Control Mapping → Prioritization → Explanations
```

### 1. **Windows Scanner** 📊
Extracts:
- Operating System & build version
- Missing security patches (KB numbers)
- Exposed services (RpcSs, WinRM, etc.)
- Open network ports
- Active processes & services

### 2. **Semantic Search (RAG)** 🔍
Uses FAISS vector index to match:
- Detected vulnerabilities → Known security controls
- Semantic similarity (not just keyword matching)
- 5,315+ CVEs in knowledge base
- Handles variations & synonyms

### 3. **Recommendation Engine** 💡
Maps controls to implementation:
- Registry modifications
- Network firewall rules
- Service configuration changes
- System hardening procedures
- Full PowerShell scripts

### 4. **AI Prioritization** 🎯
Ranks recommendations by:
- **Risk:** EPSS exploit probability (60%) + KEV known exploitation (30%)
- **Effort:** Implementation complexity by technique (10%)
- **Formula:** `priority = (risk * 0.7) + ((1-effort) * 0.3)`
- **Result:** Do highest-impact, easiest-fixes first

### 5. **Explainability** 📋
Every recommendation includes:
- **Confidence Score:** How certain is the AI (0-100%)
- **RAG Match Reason:** Why this control matched the CVE
- **Priority Rationale:** Why this ranking
- **Risk Factors:** What makes this high-risk
- **Effort Factors:** What makes this easy/hard to implement
- **Applicability:** YES/MAYBE/NO based on system config
- **Audit Trail:** Complete decision log for compliance

## 🏆 What You Get

### For SOC Analysts
✅ Smart prioritization (skip the obvious, focus on impact)  
✅ Complete explanations (understand WHY each recommendation)  
✅ Ready-to-execute scripts (copy-paste implementation)  
✅ Confidence scores (trust the recommendations)  
✅ Audit trail (prove what was done)

### For IT Teams
✅ Offline operation (works on air-gapped systems)  
✅ Legacy Windows support (covers XP/7/Server 2008+)  
✅ Simple deployment (one launcher script)  
✅ No cloud dependency (data stays local)  
✅ Minimal resource footprint

### For Security Managers
✅ Actionable intelligence (not just alerts)  
✅ Risk-weighted prioritization (limited resources go to high-impact fixes)  
✅ Compliance audit trails (traceable decisions)  
✅ Scalable recommendations (handle 5000+ CVEs)

## 📁 Project Structure

```
SmartPatch/
├── start-smartpatch.ps1              ← Run this to start
├── DEPLOYMENT.md                     ← Setup guide
├── QUICK_START.md                    ← Quick reference
├── requirements.txt                  ← Python dependencies
├── test_deployment.py                ← Verification script
│
├── src/
│   ├── api/
│   │   └── backend_api_fixed.py      ← Flask REST API
│   │
│   ├── ai/
│   │   ├── orchestration.py          ← Pipeline coordinator
│   │   ├── prioritization.py         ← Risk/effort ranking
│   │   ├── explainability.py         ← Audit trail + confidence
│   │   ├── recommendation_engine.py  ← CVE→Control mapping
│   │   └── utilities/
│   │       ├── rag_engine.py         ← Semantic search (FAISS)
│   │       └── scanner_adapter.py    ← Windows data extraction
│   │
│   ├── agent/
│   │   ├── bootstrap.py              ← System initialization
│   │   └── Check-*.ps1               ← PowerShell security checks
│   │
│   ├── database/
│   │   └── dev_db.sqlite             ← 5315 CVEs + KB mappings
│   │
│   ├── catalogues/
│   │   ├── epss.json                 ← Exploit probability scores
│   │   ├── kev.json                  ← Known exploited CVEs
│   │   └── *.json                    ← Other datasets
│   │
│   └── riskengine/
│       └── *.py                      ← Decision algorithms
│
└── html5up-spectral/
    ├── index.html                    ← Dashboard
    ├── scanner.html                  ← Scanner interface
    ├── mitigation.html               ← Recommendations page
    └── assets/js/smartpatch-api.js   ← API client
```

## 🔧 Technology Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | HTML5, JavaScript, html5up template |
| **Backend** | Python 3.9+, Flask, CORS |
| **AI/ML** | FAISS (semantic search), sentence-transformers |
| **Database** | SQLite (local, file-based) |
| **Deployment** | PowerShell launcher, standalone script |

## 📊 Data Sources

| Data | Size | Source |
|------|------|--------|
| CVE Database | 5315 CVEs | NVD (CVE Details) |
| EPSS Scores | 481 KB | Exploit Probability Scoring |
| Known Exploited (KEV) | 1.4 MB | CISA KEV Catalogue |
| KB Mappings | 10642 mappings | Windows Security Updates |
| FAISS Index | 15.6 MB | Semantic vectors |

All data is **bundled offline** - no internet required for operation.

## 🎯 Use Cases

### 1. **Legacy System Hardening**
Hospital with Windows 7 systems → Run SmartPatch → Get ranked mitigation steps → Execute safely

### 2. **Post-Breach Incident Response**
Identify systems affected by CVE → Get implementation guides → Patch in priority order

### 3. **Compliance Audit Preparation**
Document all security decisions with confidence scores → Export audit trail → Prove due diligence

### 4. **Resource-Constrained IT**
Small team, tight budget → Let AI prioritize → Focus on highest-impact fixes first

## 📈 Performance

- **Scan Time:** 1-2 minutes (Windows system enumeration)
- **Initial Prioritization:** 5-10 seconds (first CVE analysis)
- **Subsequent Scans:** <30 seconds (cached data)
- **Memory Usage:** ~200 MB (FAISS index + runtime)
- **Disk Usage:** ~1 GB (with dependencies)

## ✅ Deployment Checklist

Before deploying, verify:

```
✓ Python 3.9+ installed
✓ Port 8888 available
✓ Databases present (dev_db.sqlite, epss.json, kev.json)
✓ All source files present
✓ Launcher script permissions set
✓ Dependencies installed (pip install -r requirements.txt)
✓ test_deployment.py passes all checks
```

See **DEPLOYMENT.md** for complete setup guide.

## 🎓 Academic Features

### Clean Architecture
- Modular design (scanner, AI, API, frontend separated)
- Clear separation of concerns
- Well-documented code

### Complete Pipeline
- End-to-end from data collection to decision
- Each stage is testable independently
- Validation gates between stages

### Decision Transparency
- Every recommendation includes reasoning
- Confidence scores for all decisions
- Audit trail for compliance

### Scalability
- Handles 5315+ CVEs efficiently
- Local database (no network bottleneck)
- Optimized FAISS index

## 🚀 Next Steps (v1.1+)

- WebSocket real-time dashboard updates
- Windows Service integration (background scanning)
- Multi-machine centralized management
- SCCM / Intune integration
- Advanced ML-based risk modeling
- Compliance report generation

## 📞 Support

- **Quick Start:** See `QUICK_START.md`
- **Deployment:** See `DEPLOYMENT.md`
- **Architecture:** See `PROJECT_STRUCTURE.md`
- **Troubleshooting:** See `DEPLOYMENT.md` section
- **Verification:** Run `python test_deployment.py`

## 📄 License

This is an academic Final Year Project. Use as-is for educational and demonstration purposes.

## 🎓 Author

**SmartPatch FYP Team**  
Built as a Final Year Project for AI-driven security infrastructure on legacy systems.

---

## Quick Command Reference

```powershell
# Start SmartPatch (everything automated)
powershell -ExecutionPolicy Bypass -File start-smartpatch.ps1

# Verify installation
python test_deployment.py

# Manual start (if launcher fails)
python -m src.api.backend_api_fixed

# Test API connectivity
curl http://localhost:8888/api/health

# View documentation
notepad DEPLOYMENT.md    # Comprehensive guide
notepad QUICK_START.md   # Quick reference
```

---

**SmartPatch v1.0** - *Intelligent security for legacy systems*

✨ **Ready to deploy in 2 minutes. Start with:** `powershell -ExecutionPolicy Bypass -File start-smartpatch.ps1`
