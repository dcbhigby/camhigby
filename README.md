# Cam Higby Map App

This repo is now set up so you can:
- keep editing locally with Codex,
- push changes to GitHub,
- auto-deploy publicly with Render.

## 1) Local Run (secure login path)

```bash
cd "/Users/cameronhigby/Documents/Playground 2"
cp .env.example .env
# edit .env values
set -a; source .env; set +a
python3 server.py
```

Open: `http://127.0.0.1:8000`

Or use:

```bash
./start_server.command
```

## 2) Git Workflow (recommended)

Use two branches:
- `main` = live production
- `staging` = test before live

```bash
git init
git add .
git commit -m "Initial map app"

git branch -M main
git checkout -b staging
```

When updating:

```bash
# on staging
git add .
git commit -m "Describe change"
git push origin staging

# after testing, merge to main
git checkout main
git merge staging
git push origin main
```

## 3) Public Hosting (Render)

This repo includes `render.yaml` for one-click infrastructure.

Render setup:
1. Push this repo to GitHub.
2. In Render, create a new Web Service from that repo.
3. Render detects `render.yaml`.
4. Set secret env vars in Render dashboard:
   - `ADMIN_USERNAME`
   - `ADMIN_PASSWORD`
5. Deploy.

Important:
- Keep admin secrets only in Render env vars (not inside HTML).
- `COOKIE_SECURE=1` is already configured for hosted HTTPS.

## 4) How ongoing edits work

1. Edit locally in this folder with Codex.
2. Commit to `staging` and push.
3. Verify the staging deployment.
4. Merge to `main` to publish live.

## 5) Current email capture behavior

Viewer email submissions are saved locally in browser storage and can be exported via admin `EMAIL LOG`.
This is device/browser-local storage, not a central DB.
