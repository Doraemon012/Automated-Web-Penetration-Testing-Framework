# Web Pentest Companion Extension

A Manifest V3 browser extension that talks to the Automated Web Pentest API so you can authenticate, trigger scans, monitor progress, and visualize findings without leaving the page you are testing.

## Feature Highlights

- **Secure Auth Flow**: Email/password login wired to `/api/auth/login`; JWT is stored in `chrome.storage.local` (optional encrypted storage can be added later).
- **Quick Scan Launcher**: Start scans for the current tab, pick scan mode, toggle JS crawler, and see real-time progress via background polling.
- **History & Reporting**: Lists `/api/scans` results, opens completed payloads, downloads JSON, and injects overlays that highlight vulnerable elements on the page.
- **Schedules**: Optional local-only scheduler triggers scans at daily/weekly/monthly cadences using the default mode you configure.
- **Tailwind UI**: Popup and options pages are styled with Tailwind-inspired utility classes for rapid iteration.

## Directory Layout

```
extension/
├── manifest.json           # MV3 manifest
├── background.js           # Service worker: auth, API client, scheduler
├── popup.html/.js          # Primary UI
├── options.html/.js        # Settings & schedules
├── contentScript.js        # In-page overlays
├── styles/
│   ├── tailwind.css        # Pre-built utilities (regenerate with Tailwind CLI)
│   └── tailwind.input.css  # Source file for Tailwind compilation
└── README.md               # This document
```

## Tailwind / Build Tooling

The repository does **not** ship a `package.json`. Install tooling in your preferred workspace before working on the extension build pipeline. Recommended dev dependencies:

```
npm install -D tailwindcss postcss autoprefixer @tailwindcss/forms
npm install -D typescript vite @types/chrome
```

Set up Tailwind once:

```
npx tailwindcss init
```

Suggested `tailwind.config.cjs` content:

```js
module.exports = {
  content: ["./extension/**/*.{html,js,ts}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      colors: {
        brand: {
          primary: "#22d3ee",
          accent: "#0ea5e9",
        },
      },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
```

Generate the CSS bundle (minify for release):

```
npx tailwindcss -i ./extension/styles/tailwind.input.css -o ./extension/styles/tailwind.css --minify --watch
```

## Loading the Extension

1. Build/refresh `styles/tailwind.css` using the command above (optional but recommended before release).
2. Open Chrome/Edge → `chrome://extensions` → enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
4. Configure your API base URL inside the extension Options page and log in with the same email/password used by the FastAPI service.

## API Expectations

- The FastAPI server must expose the Mongo-backed endpoints added earlier (`/api/auth/login`, `/api/scans`, `/api/results/{id}`, etc.).
- CORS is not required because requests originate from the extension background worker, but the API needs to be reachable from the browser network context.
- For scheduled scans, ensure the account you log in with has permission to run multiple jobs.

## TODO / Next Steps

- Add optional encryption for stored JWTs (derive key from user-supplied PIN).
- Implement UI for partial scans (headers-only, misconfig-only) exposed via future API endpoints.
- Integrate passive checks toggle once lightweight heuristics are added to the background worker.
- Wire Firefox/Safari distribution scripts (consider `web-ext` for Firefox packaging).

Feel free to tailor the UI or add additional modules; the current scaffold keeps all logic framework-free so you can drop in your preferred stack (React/Preact/Svelte) later if desired.
