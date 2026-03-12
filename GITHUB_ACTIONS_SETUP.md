# GitHub Actions setup

1. Push this project to a private GitHub repository.
2. In the repository, go to **Settings -> Secrets and variables -> Actions**.
3. Add these repository secrets:
   - `SMTP_HOST`
   - `SMTP_PORT`
   - `SMTP_USERNAME`
   - `SMTP_PASSWORD`
   - `EMAIL_FROM`
   - `EMAIL_TO`
   - `SMTP_USE_SSL`
   - `SMTP_STARTTLS`
   - `SLACK_WEBHOOK_URL` (optional)
4. Review `.github/workflows/daily_cyber_brief.yml` and adjust the cron line if you want a different schedule.
   - `0 13 * * *` means **13:00 UTC** every day.
   - GitHub Actions cron uses **UTC**, not your laptop's local timezone.
   - The workflow is pinned to current action majors and forces JavaScript actions onto **Node.js 24** to avoid the GitHub Actions Node 20 deprecation path.
5. Commit and push.
6. In the **Actions** tab, run the workflow once with **Run workflow** to test it.

## If the workflow still fails

The Node.js deprecation notice is only a warning. If the job still exits with code `1`, open the `Run daily cyber brief` step and look for the Python traceback.

Common causes:
- One or more required secrets are missing or misspelled: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM`, `EMAIL_TO`
- `SMTP_STARTTLS` / `SMTP_USE_SSL` are set incorrectly for your mail provider
- Your SMTP provider rejects the login from GitHub Actions

## Important credential cleanup

Because the original `.env` file contained live credentials, do all of the following before you push anything:

1. Delete `.env` from the repo if it is tracked.
2. Rotate your Gmail app password immediately.
3. Keep the new password only in GitHub Actions secrets or your local untracked `.env` file.
4. Do not commit `daily_cyber_brief_state.json`, `.state/`, or `.venv/`.
