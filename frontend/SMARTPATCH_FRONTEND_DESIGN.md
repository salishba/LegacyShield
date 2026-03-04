# SmartPatch Production Frontend

Professional-grade vulnerability assessment and patching interface for Windows systems, powered by HARS scoring.

## Architecture Overview

### Frontend Stack
- **React 18.2** - Component-based UI
- **Material-UI 5.14** - Enterprise design system
- **Axios 1.6** - HTTP API client
- **Vite 6.4** - Development server & build tool

### Backend Integration
- **Flask REST API** - Located at `/src/src/api/backend_api.py`
- **SQLite 3** - Runtime and prioritization databases
- **HARS Engine** - Vulnerability scoring (in `/src/src/riskengine/`)

## Pages & Modules

### 1. Analyze System Page (`/src/frontend/src/pages/AnalyzeSystem.jsx`)

**Purpose**: Triggers state checker backend and displays progress

**Features**:
- "Start Analysis" button - initiates system scan
- 5-stage progress display:
  1. System Inventory (OS metadata, architecture)
  2. Patch Detection (installed KBs)
  3. Service Analysis (registry, service states)
  4. Vulnerability Assessment (missing patches → CVEs)
  5. Risk Scoring (HARS model application)
- Real-time progress bar (0-100%)
- System info display after completion
- Error handling with retry capability

**API Endpoints**:
- `POST /api/scan` - Trigger analysis

**Data Fetching**:
- `useAnalysisScan()` hook - manages scan state
- `useSystemInfo()` hook - fetches post-scan system metadata

---

### 2. System Overview Page (`/src/frontend/src/pages/SystemOverview.jsx`)

**Purpose**: Displays system state checker output WITHOUT any risk scoring

**Features**:
- Read-only system metadata presentation:
  - Hostname, OS version, build number, architecture
  - Domain membership, elevation status
  - Last scan timestamp, agent version
- Sections: System ID, OS, Domain & Security, Status
- No HARS calculations performed on this page
- Clear indicator: "This page displays system metadata only"

**API Endpoints**:
- `GET /api/system` - System metadata

**Data Fetching**:
- `useSystemInfo()` hook

---

### 3. HARS Risk & Priority Dashboard (`/src/frontend/src/pages/RiskDashboard.jsx`)

**Purpose**: Displays aggregate vulnerability risk and HARS-based prioritization

**Features**:
- Overall risk level card (CRITICAL/HIGH/MEDIUM/LOW)
- Risk distribution breakdown:
  - HIGH priority count
  - MEDIUM priority count
  - LOW priority count
  - Progress bars with percentages
- Top 10 vulnerabilities sorted by HARS score
- Risk statistics:
  - Total vulnerability count
  - Average HARS score
  - Max/Min scores

**Vulnerability Table**:
| Column | Source |
|--------|--------|
| CVE ID | Database |
| Title | Database |
| Priority | HARS final_score (≥0.70=HIGH, ≥0.35=MEDIUM, <0.35=LOW) |
| HARS Score | final_score field |
| R/A/C Scores | attack_surface_score / reachability_score / criticality_score |

**API Endpoints**:
- `GET /api/risk-summary` - Aggregate risk stats
- `GET /api/vulnerabilities` - Detailed vulnerability list

**Data Fetching**:
- `useRiskSummary()` hook
- `useVulnerabilities()` hook

---

### 4. Mitigation Recommendations Workspace (`/src/frontend/src/pages/MitigationRecommendations.jsx`)

**Purpose**: Actionable recommendations table with detail view

**Features**:
- Searchable table of vulnerabilities with HARS scores
- Columns:
  - Priority (badge)
  - CVE ID
  - Risk Summary (title + CVSS chip)
  - HARS Score (color-coded)
  - Detection Confidence (%)
  - Actions (Details button)
- Pagination (5, 10, 25, 50 rows per page)
- Sort by priority (HIGH → MEDIUM → LOW)

**Detail Dialog** (RecommendationDetailDialog):
- **Risk Context**: Vulnerability, component, reason
- **Evidence from State Checker**:
  - Missing KB ID
  - Detection method
  - Confidence percentage
- **HARS Scoring Breakdown**:
  - R Score (Reachability)
  - A Score (Exploitability/Attack Surface)
  - C Score (Criticality/Impact)
  - Final Score (0.0-1.0)
- **AI Reasoning** (bullet points):
  - Why unpatched
  - CVSS factor
  - Priority determination
  - Mitigation availability
- **Mitigation Plan**:
  - Recommended action (e.g., "Install KB XXXXX")
  - Preconditions (backup, no critical processes)
  - PowerShell script (expandable/copyable)
  - Rollback instructions

**API Endpoints**:
- `GET /api/vulnerabilities` - Full vulnerability list

**Data Fetching**:
- `useVulnerabilities()` hook

**Important**: 
- ✓ No automatic script execution
- ✓ Scripts are for manual review and execution only
- ✓ All values fetched from backend (no fabrication)

---

### 5. Logs & Audit Page (`/src/frontend/src/pages/AuditLogs.jsx`)

**Purpose**: Immutable audit trail of scans and HARS batches

**Features**:
- Summary stats:
  - Total scans
  - Last scan date
  - Unique hosts
  - Audit status (Active)
- Scan history table:
  - Timestamp
  - Host hash
  - Hostname
  - OS caption
  - Build number
  - Details button

**Scan Detail Dialog** (ScanDetailDialog):
- Timestamp
- Host hash
- Hostname
- OS version & build
- Architecture
- Audit notes (immutable indicator)

**API Endpoints**:
- `GET /api/scans` - Historical scans

**Data Fetching**:
- `useScanHistory()` hook

---

## Data Fetching Architecture

### API Client (`/src/frontend/src/api/backend.js`)

**Base URL**: `http://localhost:8888/api`

**Endpoints**:

| Method | Endpoint | Returns | Purpose |
|--------|----------|---------|---------|
| POST | `/scan` | `{ success, message, scan_output }` | Trigger analysis |
| GET | `/system` | System metadata object | Current system info |
| GET | `/scans` | `{ scans: [...] }` | Historical scans |
| GET | `/scan/<id>` | Scan details | Single scan info |
| GET | `/vulnerabilities` | `{ vulnerabilities: [...] }` | All vulns with HARS |
| GET | `/risk-summary` | `{ summary: {...} }` | Aggregate risk stats |
| GET | `/installed-kbs` | `{ kbs: [...] }` | KB list |
| GET | `/health` | `{ status: string }` | Backend status |

### Custom Hooks (`/src/frontend/src/hooks/useSmartPatch.js`)

**Data Fetching Hooks**:
- `useSystemInfo()` - Fetch system metadata
- `useRiskSummary()` - Aggregate risk distribution
- `useVulnerabilities()` - Full vulnerability list with HARS
- `useScanHistory()` - Historical scan records
- `useInstalledKbs()` - Installed patches
- `useAnalysisScan()` - Trigger scan + progress tracking

**Hook Interface**:
```javascript
const { data, loading, error, refetch } = useHookName();
```

---

## Reusable Components (`/src/frontend/src/components/SmartPatchUI.jsx`)

### Component Library

| Component | Purpose |
|-----------|---------|
| `<HARSScoreCard>` | Display R/A/C/final scores |
| `<RiskBadge>` | Colored priority indicator |
| `<ScanProgress>` | Progress bar + status message |
| `<LoadingState>` | Skeleton/spinner |
| `<ErrorState>` | Error message + retry |
| `<EmptyState>` | No data placeholder |
| `<SystemInfoDisplay>` | Formatted system metadata |

---

## HARS Score Interpretation

**Final Score Range**: 0.0 (lowest risk) to 1.0 (highest risk)

**Priority Classification**:
- **HIGH**: final_score ≥ 0.70 (red, immediate attention)
- **MEDIUM**: 0.35 ≤ final_score < 0.70 (orange, planned)
- **LOW**: final_score < 0.35 (green, low concern)

**Component Scores**:
- **R Score**: Reachability (network/local access possibility)
- **A Score**: Exploitability & Attack Surface (ease of exploitation)
- **C Score**: Criticality & Impact (data/system compromise)

**Example Interpretation**:
```
CVE-2023-1234:
  R: 0.85 (highly reachable)
  A: 0.72 (easily exploitable)
  C: 0.68 (high impact if compromised)
  Final: 0.75 → HIGH priority
```

---

## Error Handling Strategy

### Missing Data
If HARS fields are missing:
- Display "N/A" or "—" instead of fabricating values
- Log warning to console
- Show "Data not available" message to user

### Backend Connection
- Health check every 30 seconds
- Display connection status in AppBar
- Show alert if backend unreachable
- Error state includes retry capability

### Empty States
- Distinguished from error states
- Helpful message (e.g., "Run Analysis to generate data")
- Never show fallback mock data

---

## DEFINITION OF DONE ✓

- ✓ User can trigger system analysis (Analyze System page)
- ✓ System metadata matches state checker output (System Overview)
- ✓ HARS dashboard displays stored HARS calculations (Risk Dashboard)
- ✓ Recommendations reflect AI/HARS module output (Recommendations table)
- ✓ Evidence matches state checker data (Detail dialog)
- ✓ No hardcoded CVE or CVSS data (all from backend)
- ✓ No mitigation auto-execution (manual review required)
- ✓ Offline-only, SQLite-backed
- ✓ No mock data in production
- ✓ Immutable audit trail (Audit Logs)

---

## Running the Frontend

### Development Mode
```bash
cd /src/frontend
npm install
npm run dev
```

Frontend runs at: `http://localhost:5173`

### Backend Setup
```bash
cd /src
python src/api/backend_api.py --port 8888 --db runtime_scan.sqlite
```

Backend runs at: `http://localhost:8888/api`

### Production Build
```bash
cd /src/frontend
npm run build
# Output: /src/frontend/dist/
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                   SmartPatch Frontend                   │
│                   (React + Material-UI)                 │
├─────────────────────────────────────────────────────────┤
│  Pages:                                                 │
│  • Analyze System       (triggers scan)                 │
│  • System Overview      (metadata only)                 │
│  • Risk Dashboard       (HARS scores)                   │
│  • Recommendations     (mitigation plans)               │
│  • Audit Logs          (scan history)                   │
├─────────────────────────────────────────────────────────┤
│  Hooks:                                                 │
│  • useSystemInfo()      • useRiskSummary()              │
│  • useVulnerabilities() • useScanHistory()              │
│  • useAnalysisScan()                                    │
├─────────────────────────────────────────────────────────┤
│  API Client (Axios)                                     │
│  Base: http://localhost:8888/api                        │
├─────────────────────────────────────────────────────────┤
│              Flask Backend (/src/src/api/)              │
├─────────────────────────────────────────────────────────┤
│  Databases:                                             │
│  • runtime_scan.sqlite (system + patch data)            │
│  • prioritization.db (HARS scores)                      │
│  • mitigations_catalogue.sqlite (CVE data)              │
└─────────────────────────────────────────────────────────┘
```

---

## Key Design Principles

1. **Read-Only Interface**: Frontend cannot modify backend data
2. **HARS-Driven**: All risk calculations come from backend HARS engine
3. **No AI Inference**: Frontend displays AI output, doesn't generate it
4. **State Checker Source**: System data comes only from state checker
5. **Immutable Audit**: All records are timestamped and read-only
6. **Offline SQLite**: No external dependencies or cloud connectivity
7. **Error Transparency**: Missing data documented, never fabricated

---

## Support & Troubleshooting

### Frontend won't connect to backend
- Check backend is running: `python src/api/backend_api.py`
- Check port 8888 is available
- Check firewall rules (localhost should be allowed)

### HARS scores not displaying
- Ensure vulnerabilities table has `hars_score` and `priority` fields
- Run HARS engine: `python src/src/riskengine/hars.py --run-all`
- Check `prioritization.db` exists and has data

### System info shows "N/A"
- Ensure analysis was run (Analyze System page)
- Check `runtime_scan.sqlite` has `system_info` table with data

### No vulnerabilities showing
- Run analysis first (Analyze System)
- Check CVE/patch data exists in `mitigations_catalogue.sqlite`
- Verify HARS scoring completed

---

## Version History

- **v1.0.0** - Initial production release
  - 5 main pages
  - HARS integration
  - Offline-first architecture
  - Immutable audit trail
