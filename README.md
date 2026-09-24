# FreeFire Info API — OB55

This package is configured for the OB55 release and provides a Flask `/player-info` endpoint.

## Endpoints
- `GET /health` — local service health and configured release/regions.
- `GET /player-info?uid=<UID>&region=<REGION>` — fetch player information.
- `POST /refresh` — refresh cached login tokens (use only on a trusted deployment).

## OB55
`RELEASEVERSION` is set to `OB55` and is sent on login and player-info requests.

## Supported region codes
IND, BR, US, SAC, NA, SG, RU, ID, TW, VN, TH, ME, PK, CIS, BD, EUROPE.
Aliases include EU -> EUROPE.

## Important
The package is made deployment-ready with lazy token creation, retries, timeout handling, and a health endpoint. Actual upstream OB55 availability depends on the upstream Garena services, valid credentials, server URLs, and current protocol compatibility; the package cannot guarantee that every region is live at every moment.

Do not publish real account credentials. Prefer environment variables or a private `accounts.txt` outside public source control.
