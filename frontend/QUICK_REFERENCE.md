# SmartPatch Frontend - Quick Reference Guide

## Running the Application

### Development Mode
```bash
cd frontend/
npm install
npm run dev
```
Starts Vite dev server @ `http://localhost:5173`

### Production Build
```bash
npm run build
npm run preview
```
Creates optimized bundle in `dist/` directory

## Architecture at a Glance

```
React App (Frontend)
    ↓
Axios HTTP Client
    ↓  
Flask Backend API
    ↓
SQLite Databases
```

## Key Files

| File | Purpose |
|------|---------|
| `src/api/backend.js` | REST client, all API calls |
| `src/hooks/useSmartPatch.js` | React hooks for data fetching |
| `src/App.jsx` | Main app container, navigation |
| `src/pages/*.jsx` | Dashboard pages |
| `src/components/SmartPatchUI.jsx` | Reusable UI components |
| `.env.development` | Dev API URL |
| `.env.production` | Prod API URL |

## Data Flow

### System Overview Page
```
Page Mount
  ↓
useSystemInfo() hook fires
  ↓
GET /api/system
  ↓
Backend queries SQLite
  ↓
JSON response
  ↓
Component renders system info
```

All other pages follow the same pattern.

## Available Endpoints

**System**
- GET /api/health → Backend health status
- GET /api/system → Latest system info
- GET /api/scans → List all scans
- GET /api/scan/{id} → Get scan details

**Vulnerabilities**
- GET /api/vulnerabilities → CVE list with HARS scores
- GET /api/risk-summary → Risk distribution
- GET /api/installed-kbs → Installed patches

**Recommendations**
- GET /api/recommendations → AI mitigations
- GET /api/mitigation/{cve_id} → Mitigation details

**Audit**
- GET /api/audit-logs → Scan history

**Orchestration**
- POST /api/scan → Trigger new scan

## React Hooks Pattern

All data hooks return same structure:
```javascript
const { data, loading, error, refetch } = useXxx();

// Display based on state
if (loading) return <LoadingState />;
if (error) return <ErrorState message={error} />;
if (!data) return <EmptyState />;
return <DataDisplay data={data} />;
```

## Environment Variables

**Development** (`.env.development`)
```env
VITE_API_URL=http://localhost:8888/api
```

**Production** (`.env.production`)
```env
VITE_API_URL=https://your-backend.com/api
```

## Error Handling

API errors throw and propagate to UI:
```javascript
try {
  const data = await systemAPI.getSystemInfo();
  setSystem(data);
} catch (err) {
  setError(err.message);  // Shows user-facing error
}
```

No silent failures or fallback data.

## Build Output

```
dist/
├── index.html              (0.5 KB)
└── assets/
    ├── index-*.css        (0.5 KB)
    └── index-*.js         (486 KB)
```

Ready to deploy anywhere.

## Pages & Responsibilities

| Page | Loads | Displays |
|------|-------|----------|
| Analyze System | - | Scan button, system info |
| System Overview | /api/system, /api/installed-kbs | Metadata, patches |
| Risk Dashboard | /api/risk-summary, /api/vulnerabilities | Risk distribution, top CVEs |
| Recommendations | /api/recommendations, /api/mitigation/* | Prioritized mitigations |
| Audit Logs | /api/audit-logs | Scan history |

## Important Notes

✅ **All data from backend** - Zero mock data
✅ **Fail loudly** - Errors displayed visibly
✅ **Real-time** - Fresh data on each page load
✅ **Production ready** - No console.logs, no debugging code
✅ **No hardcoding** - Config via environment variables

## Troubleshooting

### "Failed to fetch system information"
- Check backend running: `http://localhost:8888/api/health`
- Check VITE_API_URL configured correctly
- Check CORS enabled on backend

### "No data available"
- Run a scan first: POST /api/scan
- Wait for scan to complete
- Refresh page to reload data

### Build fails
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
npm run build
```

## Testing

### Development
1. Run `npm run dev`
2. Navigate to `http://localhost:5173`
3. Open DevTools (F12) to inspect network requests
4. Each page should show real data from backend

### Production Build
```bash
npm run build
npm run preview
# Visit http://localhost:4173
```

## Key Concepts

**API Client**: `backend.js` - Single point of all HTTP calls
**Hooks**: `useSmartPatch.js` - Data fetching & state management
**Pages**: Consume hooks, render based on state
**Components**: Reusable UI elements
**Error Handling**: UI shows all errors clearly
**Backend Dependency**: All logic in Flask/database, not frontend

---

For detailed documentation, see:
- `PRODUCTION_CHECKLIST.md` - Deployment verification
- `PRODUCTION_FINAL_DELIVERY.md` - Complete final delivery notes
- `SMARTPATCH_FRONTEND_DESIGN.md` - Original design documentation
