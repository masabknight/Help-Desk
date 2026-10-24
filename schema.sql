CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_no TEXT NOT NULL UNIQUE,          -- login id (student reg no / staff id)
    name            TEXT NOT NULL,
    password_hash   TEXT NOT NULL,                 -- salt$PBKDF2-SHA256 hex, never plain text
    role            TEXT NOT NULL CHECK (role IN ('student','operator','administrator'))
);

CREATE TABLE IF NOT EXISTS requests (
    request_id  INTEGER PRIMARY KEY AUTOINCREMENT, -- AUTOINCREMENT: ids never reused, survive restart
    user_id     INTEGER NOT NULL REFERENCES users(user_id),
    category    TEXT NOT NULL CHECK (category IN ('Registration','Fee Issue','Examination','Other')),
    description TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Pending'
                CHECK (status IN ('Pending','Processing','Resolved','Rejected')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    assigned_to INTEGER REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS request_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL REFERENCES requests(request_id),
    changed_by INTEGER NOT NULL REFERENCES users(user_id),
    old_status TEXT,
    new_status TEXT NOT NULL,
    remarks    TEXT,
    changed_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_requests_user   ON requests(user_id);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
CREATE INDEX IF NOT EXISTS idx_history_request ON request_history(request_id);
