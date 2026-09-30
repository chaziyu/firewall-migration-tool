# React frontend

The React app uses the existing Flask `/api/*` endpoints. Flask serves the production build from `dist/` at `/`.

## Development

Install dependencies and run Vite from this directory:

```powershell
npm ci
npm run dev
```

Run the Flask app separately on port 5000 so Vite can proxy API calls and fonts.

## Build and desktop packaging

From this directory, run `npm run build` before packaging the desktop app. The PyInstaller spec includes `src/frontend/dist`; that directory is generated and is not committed.

The app currently includes configuration reporting, Excel export, live collection and snapshot import/export, FortiGate to PAN-OS review, rendered migration downloads, and controlled candidate deployment.
