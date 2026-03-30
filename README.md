# luadec bot + server

This project now uses the cleaner setup:

- the Flask server is the only delivery path the client sees
- the Discord bot is only the upload front end
- Firebase is private persistence for the server, not a public fallback the client reads

## Main flow

1. A user uploads a Lua file through the Discord bot.
2. The bot sends the script to your server.
3. The server stores the script record in Firestore.
4. The bot replies with the final loader snippet only.
5. The bot replies with a short loader snippet that only points at your server.

## Important tradeoff

This is the stronger design. The key is validated server-side before the raw script is served, and the client never gets shown a Firebase URL.

Firebase is only there so the server can recover scripts after restarts or memory loss. If the server is completely offline, the loader will not work until the server is back.

## Environment

Copy `.env.example` to `.env`.

Required for both:

- `FIREBASE_PROJECT_ID`
- `FIREBASE_COLLECTION`
- `FIREBASE_SERVICE_ACCOUNT_PATH` or `FIREBASE_SERVICE_ACCOUNT_JSON`
- `SERVER_UPLOAD_API_KEY`

Required for the bot:

- `DISCORD_TOKEN`
- `SERVER_BASE_URL`

Required for the server:

- `PUBLIC_BASE_URL`
- `SERVER_SECRET`

Optional:

- `PORT`
- `SIGNED_URL_TTL_SECONDS`
- `RATE_LIMIT_WINDOW_SECONDS`

## Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run the server

```powershell
python server.py
```

## Run the bot

```powershell
python bot.py
```

## Render deploy

This server is now prepared for Render with:

- [render.yaml](C:/Users/Flames/Documents/luadec/render.yaml)
- [wsgi.py](C:/Users/Flames/Documents/luadec/wsgi.py)

To deploy on Render:

1. Put this folder in a Git repo.
2. Push it to GitHub, GitLab, or Bitbucket.
3. In Render, create a new Blueprint or web service from that repo.
4. Set these environment variables in Render:
   - `PUBLIC_BASE_URL`
   - `SERVER_UPLOAD_API_KEY`
   - `SERVER_SECRET`
   - `FIREBASE_PROJECT_ID`
   - `FIREBASE_SERVICE_ACCOUNT_JSON`
   - optional: `FIREBASE_COLLECTION`

For `PUBLIC_BASE_URL`, use your Render service URL after creation, for example:

```txt
https://luadec-server.onrender.com
```

For `FIREBASE_SERVICE_ACCOUNT_JSON`, paste the full JSON contents of your Firebase service account key as one env var value.

## Firestore rules

Use `Firestore`, not `Realtime Database`.

The included `firestore.rules` file should stay locked down in Firestore Rules:

```txt
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```
