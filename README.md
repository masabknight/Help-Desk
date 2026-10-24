# University Help Desk Management System

C++ (Crow) server + array-based circular queue + SQLite + browser dashboards.

## Build & run (Ubuntu/Debian)
    sudo apt install build-essential cmake git libasio-dev libsqlite3-dev libssl-dev
    cmake -S . -B build && cmake --build build -j
    ./build/queue_test            # Phase 1: queue unit tests
    ./build/helpdesk              # run from the project folder (needs db/ and static/)

Environment options: `PORT` (8080), `QUEUE_CAPACITY` (5), `DB_PATH` (helpdesk.db).
Open `http://localhost:8080` or, from another computer, `http://<server-LAN-IP>:8080`
(allow the port in the firewall, e.g. `sudo ufw allow 8080/tcp`).

## Demo accounts (created on first run)
| Login ID | Password | Role |
|---|---|---|
| ADMIN01 | admin123 | administrator |
| OP01, OP02 | op123 | operator |
| 2024-CS-001 … 004 | student123 | student |

## Key points
- Queue ops (enqueue/dequeue/peek/display) are O(1)/O(1)/O(1)/O(n); wraparound: `(i+1) % capacity`.
- A global mutex makes queue + DB changes atomic (no lost submissions, no double-processing).
- Full queue → HTTP 409, request is not saved. Processing = dequeue + status `Processing` (not resolved).
- On restart the queue is rebuilt from `Pending` rows ordered by `request_id`.
- Students see only their own requests; operators update only requests assigned to them; admins see reports and can assign.
- Passwords: salted PBKDF2-SHA256. All SQL is parameterized.
- Demo uses plain HTTP; use HTTPS (reverse proxy) for real deployment.
