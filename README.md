# GIO DriveAI login

## Run locally

Requires Node.js 22.13 or newer. No npm dependencies are needed.

```powershell
node server.js
```

Open [http://localhost:3000](http://localhost:3000). The SQLite database is created as `gio-driveai.sqlite` in this folder and should be backed up with the application data.

## Enable GIO DriveAI chat with Gemini

The server loads environment variables from a `.env` file in this project folder at startup. Add the key locally like this (replace the placeholder with a newly rotated Gemini key):

```powershell
GEMINI_API_KEY=your-gemini-api-key
# Optional; gemini-2.5-flash is the default
GEMINI_MODEL=gemini-flash-lite-latest
```

Alternatively, set these variables in the server process environment. Do not put the key in `index.html`, commit it, or send it to the browser. `.env` is excluded by `.gitignore`.

Restart the server after editing `.env`:

```powershell
node server.js
```

Sign in to see the assistant panel. Chat requests are session-authenticated, limited to 20 messages per account per minute, capped to the recent 12 messages, and forwarded server-to-server to Gemini. Without `GEMINI_API_KEY`, the chat remains usable with built-in local guidance for greetings, vehicle care, driving safety and app capabilities; it clearly identifies that local mode does not provide live data or full generative AI. If Gemini errors, the server returns the same local guidance instead of leaving the chat without a response.

## Available flows

- Account registration and sign-in with scrypt-hashed passwords.
- Authenticated GIO DriveAI chat powered by Gemini when the server key is configured.
- The requested local driver account can sign in with username `Angelo Dairo`. Its requested password is weak; use it only on this local demo and change it before exposing the app to a network.
- Because no account email was provided, this local account uses a reserved non-deliverable address. Password recovery for it will not reach an inbox; update its email before relying on recovery.
- Persistent, HTTP-only sign-in sessions and sign-out.
- Local password recovery codes, valid for five minutes. The code is returned by the backend for the local development flow. In production, configure an email delivery provider before enabling password recovery.
- Vehicle pairing creates a five-minute one-time code. A vehicle companion service still needs to be integrated to redeem pairing codes.
- The menu and layout setting are local UI actions.

For a production deployment, use HTTPS, set `NODE_ENV=production`, and integrate email delivery and the vehicle companion service. Recovery codes are intentionally not returned by the API in production mode.
