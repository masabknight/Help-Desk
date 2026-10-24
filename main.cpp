// University Help Desk Management System - central C++ server
// Crow (HTTP) + SQLite (persistence) + array-based circular queue (pending FIFO).
// All queue operations happen here, never in the browser.
#include "crow.h"
#include "CircularQueue.h"
#include <sqlite3.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>

using Row = std::vector<std::string>;
static sqlite3* db = nullptr;
static CircularQueue* Q = nullptr;
static std::mutex gMtx;   // guards queue + database together (atomic queue/DB updates)

// ---------------------------------------------------------------- DB helpers
struct Stmt {
    sqlite3_stmt* s = nullptr;
    explicit Stmt(const std::string& sql) {
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db));
    }
    ~Stmt() { sqlite3_finalize(s); }
    void bind(int i, const std::string& v) { sqlite3_bind_text(s, i, v.c_str(), (int)v.size(), SQLITE_TRANSIENT); }
    void bind(int i, long long v) { sqlite3_bind_int64(s, i, v); }
};
static void bindAll(Stmt&, int) {}
template <class T, class... R> static void bindAll(Stmt& s, int i, const T& v, const R&... r) {
    s.bind(i, v); bindAll(s, i + 1, r...);
}
// Parameterized queries only: user input is never concatenated into SQL.
template <class... A> static std::vector<Row> query(const std::string& sql, const A&... a) {
    Stmt st(sql); bindAll(st, 1, a...);
    std::vector<Row> out; int n = sqlite3_column_count(st.s);
    while (sqlite3_step(st.s) == SQLITE_ROW) {
        Row r;
        for (int c = 0; c < n; c++) { auto p = sqlite3_column_text(st.s, c); r.push_back(p ? (const char*)p : ""); }
        out.push_back(r);
    }
    return out;
}
template <class... A> static long long exec(const std::string& sql, const A&... a) {
    Stmt st(sql); bindAll(st, 1, a...);
    if (sqlite3_step(st.s) != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(db));
    return sqlite3_last_insert_rowid(db);
}
struct Tx {   // rolls back automatically unless commit() is called
    bool done = false;
    Tx() { exec("BEGIN"); }
    void commit() { exec("COMMIT"); done = true; }
    ~Tx() { if (!done) sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr); }
};

// ------------------------------------------------------------ passwords/tokens
static std::string hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef"; std::string o;
    for (size_t i = 0; i < n; i++) { o += d[p[i] >> 4]; o += d[p[i] & 15]; }
    return o;
}
static std::string randomHex(size_t n) {
    std::vector<unsigned char> b(n); RAND_bytes(b.data(), (int)n); return hex(b.data(), n);
}
static std::string pbkdf(const std::string& pw, const std::string& salt) {
    unsigned char out[32];
    PKCS5_PBKDF2_HMAC(pw.c_str(), (int)pw.size(), (const unsigned char*)salt.data(), (int)salt.size(),
                      100000, EVP_sha256(), 32, out);
    return hex(out, 32);
}
static std::string makeHash(const std::string& pw) { std::string s = randomHex(16); return s + "$" + pbkdf(pw, s); }
static bool verifyPw(const std::string& pw, const std::string& stored) {
    auto p = stored.find('$'); if (p == std::string::npos) return false;
    std::string h = stored.substr(p + 1), c = pbkdf(pw, stored.substr(0, p));
    return h.size() == c.size() && CRYPTO_memcmp(h.data(), c.data(), h.size()) == 0;
}

struct Session { int uid; std::string role, name; };
static std::map<std::string, Session> sessions;
static std::mutex sessMtx;
static std::optional<Session> getSession(const crow::request& req) {
    std::string h = req.get_header_value("Authorization");
    if (h.rfind("Bearer ", 0) != 0) return std::nullopt;
    std::lock_guard<std::mutex> l(sessMtx);
    auto it = sessions.find(h.substr(7));
    if (it == sessions.end()) return std::nullopt;
    return it->second;
}
static bool isStaff(const Session& s) { return s.role == "operator" || s.role == "administrator"; }

// ----------------------------------------------------------------- utilities
static crow::response err(int code, const std::string& m) {
    crow::json::wvalue j; j["error"] = m; return crow::response(code, j);
}
#define AUTH(S, CHECK) \
    auto S##_o = getSession(req); if (!S##_o) return err(401, "Please log in first"); \
    const Session& S = *S##_o; if (!(CHECK)) return err(403, "Access denied: you do not have permission for this action");

static std::string jstr(const crow::json::rvalue& b, const char* k) {
    if (!b.has(k) || b[k].t() != crow::json::type::String) return "";
    return std::string(b[k].s());
}
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
template <class F> static auto safe0(F f) {
    return [f](const crow::request& req) -> crow::response {
        try { return f(req); } catch (const std::exception& e) { std::cerr << "[error] " << e.what() << "\n"; return err(500, "Internal server error"); }
    };
}
template <class F> static auto safe1(F f) {
    return [f](const crow::request& req, int id) -> crow::response {
        try { return f(req, id); } catch (const std::exception& e) { std::cerr << "[error] " << e.what() << "\n"; return err(500, "Internal server error"); }
    };
}

static const char* REQ_SEL =
    "SELECT r.request_id,u.registration_no,u.name,r.category,r.description,r.status,r.created_at,r.updated_at,"
    "COALESCE(a.name,'') FROM requests r JOIN users u ON u.user_id=r.user_id "
    "LEFT JOIN users a ON a.user_id=r.assigned_to ";

static void reqJson(crow::json::wvalue& w, const Row& r) {
    w["request_id"] = std::stoll(r[0]); w["registration_no"] = r[1]; w["student_name"] = r[2];
    w["category"] = r[3]; w["description"] = r[4]; w["status"] = r[5];
    w["created_at"] = r[6]; w["updated_at"] = r[7]; w["assigned_to"] = r[8];
}
static void statsJson(crow::json::wvalue& w) {
    std::map<std::string, long long> m{{"Pending", 0}, {"Processing", 0}, {"Resolved", 0}, {"Rejected", 0}};
    for (auto& r : query("SELECT status,COUNT(*) FROM requests GROUP BY status")) m[r[0]] = std::stoll(r[1]);
    for (auto& kv : m) w[kv.first] = kv.second;
}
static void addHistory(long long reqId, int by, const std::string& oldS, const std::string& newS, const std::string& rem) {
    exec("INSERT INTO request_history(request_id,changed_by,old_status,new_status,remarks) VALUES(?,?,?,?,?)",
         reqId, by, oldS, newS, rem);
}
static void seedUsers() {
    if (!query("SELECT 1 FROM users LIMIT 1").empty()) return;
    struct U { const char *id, *name, *pw, *role; };
    U us[] = {{"ADMIN01", "System Administrator", "admin123", "administrator"},
              {"OP01", "Operator One", "op123", "operator"},
              {"OP02", "Operator Two", "op123", "operator"},
              {"2024-CS-001", "Ali Khan", "student123", "student"},
              {"2024-CS-002", "Sara Ahmed", "student123", "student"},
              {"2024-CS-003", "Usman Raza", "student123", "student"},
              {"2024-CS-004", "Hina Malik", "student123", "student"}};
    for (auto& u : us)
        exec("INSERT INTO users(registration_no,name,password_hash,role) VALUES(?,?,?,?)", u.id, u.name, makeHash(u.pw), u.role);
    std::cout << "Seeded demo users (ADMIN01/admin123, OP01/op123, 2024-CS-001/student123 ...)\n";
}

int main() {
    const char* e;
    int cap = (e = getenv("QUEUE_CAPACITY")) ? std::max(1, atoi(e)) : 5;
    int port = (e = getenv("PORT")) ? atoi(e) : 8080;
    std::string dbPath = (e = getenv("DB_PATH")) ? e : "helpdesk.db";

    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) { std::cerr << "Cannot open database\n"; return 1; }
    sqlite3_busy_timeout(db, 3000);
    sqlite3_exec(db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    {
        std::ifstream f("db/schema.sql");
        if (!f) { std::cerr << "db/schema.sql not found - run the server from the project folder\n"; return 1; }
        std::stringstream ss; ss << f.rdbuf(); char* em = nullptr;
        if (sqlite3_exec(db, ss.str().c_str(), nullptr, nullptr, &em) != SQLITE_OK) { std::cerr << "Schema error: " << em << "\n"; return 1; }
    }
    seedUsers();

    // Server restart: rebuild the pending queue from the database in FIFO (request_id) order.
    Q = new CircularQueue(cap);
    for (auto& r : query("SELECT r.request_id,r.user_id,u.registration_no,r.category,r.description,r.created_at "
                         "FROM requests r JOIN users u ON u.user_id=r.user_id WHERE r.status='Pending' "
                         "ORDER BY r.request_id LIMIT ?", cap)) {
        QueueItem it; it.requestId = std::stoi(r[0]); it.userId = std::stoi(r[1]); it.regNo = r[2];
        it.category = r[3]; it.description = r[4]; it.createdAt = r[5];
        Q->enqueue(it);
    }
    std::cout << "Queue capacity " << cap << ", recovered " << Q->size() << " pending request(s)\n";

    crow::SimpleApp app;

    // ------------------------------------------------------------ static pages
    CROW_ROUTE(app, "/")([](const crow::request&, crow::response& res) { res.set_static_file_info("static/index.html"); res.end(); });
    CROW_ROUTE(app, "/student")([](const crow::request&, crow::response& res) { res.set_static_file_info("static/student.html"); res.end(); });
    CROW_ROUTE(app, "/admin")([](const crow::request&, crow::response& res) { res.set_static_file_info("static/admin.html"); res.end(); });

    // -------------------------------------------------------------- auth
    CROW_ROUTE(app, "/api/login").methods("POST"_method)(safe0([](const crow::request& req) -> crow::response {
        auto b = crow::json::load(req.body);
        if (!b) return err(400, "Login ID and password are required");
        std::string id = trim(jstr(b, "login_id")), pw = jstr(b, "password");
        if (id.empty() || pw.empty()) return err(400, "Login ID and password are required");
        std::vector<Row> rows;
        { std::lock_guard<std::mutex> lk(gMtx);
          rows = query("SELECT user_id,name,password_hash,role FROM users WHERE registration_no=?", id); }
        if (rows.empty() || !verifyPw(pw, rows[0][2])) return err(401, "Invalid login ID or password");
        std::string tok = randomHex(24);
        Session s{std::stoi(rows[0][0]), rows[0][3], rows[0][1]};
        { std::lock_guard<std::mutex> l(sessMtx); sessions[tok] = s; }
        crow::json::wvalue j; j["token"] = tok; j["role"] = s.role; j["name"] = s.name;
        return crow::response(200, j);
    }));
    CROW_ROUTE(app, "/api/logout").methods("POST"_method)(safe0([](const crow::request& req) -> crow::response {
        std::string h = req.get_header_value("Authorization");
        if (h.rfind("Bearer ", 0) == 0) { std::lock_guard<std::mutex> l(sessMtx); sessions.erase(h.substr(7)); }
        crow::json::wvalue j; j["ok"] = true; return crow::response(200, j);
    }));

    // ------------------------------------------------- student: submit request
    CROW_ROUTE(app, "/api/requests").methods("POST"_method)(safe0([](const crow::request& req) -> crow::response {
        AUTH(s, s.role == "student");
        auto b = crow::json::load(req.body);
        if (!b) return err(400, "Invalid request data");
        std::string cat = jstr(b, "category"), desc = trim(jstr(b, "description"));
        if (cat.empty()) return err(400, "Please select a category");
        if (cat != "Registration" && cat != "Fee Issue" && cat != "Examination" && cat != "Other")
            return err(400, "Invalid category");
        if (desc.empty()) return err(400, "Please enter a description");
        if (desc.size() > 1000) return err(400, "Description is too long (max 1000 characters)");

        std::lock_guard<std::mutex> lk(gMtx);
        if (Q->isFull())   // checked BEFORE saving: a rejected request is never stored or overwritten
            return err(409, "The pending queue is full (capacity " + std::to_string(Q->capacity()) + "). Please try again later.");
        long long id;
        { Tx tx;
          id = exec("INSERT INTO requests(user_id,category,description) VALUES(?,?,?)", s.uid, cat, desc);
          addHistory(id, s.uid, "", "Pending", "Request submitted");
          tx.commit(); }
        auto r = query("SELECT u.registration_no,r.created_at FROM requests r JOIN users u ON u.user_id=r.user_id WHERE r.request_id=?", id);
        QueueItem it; it.requestId = (int)id; it.userId = s.uid; it.regNo = r[0][0];
        it.category = cat; it.description = desc; it.createdAt = r[0][1];
        Q->enqueue(it);
        crow::json::wvalue j; j["request_id"] = id; j["status"] = "Pending";
        j["message"] = "Request submitted successfully. Your request ID is " + std::to_string(id);
        return crow::response(201, j);
    }));

    CROW_ROUTE(app, "/api/my-requests")(safe0([](const crow::request& req) -> crow::response {
        AUTH(s, s.role == "student");
        std::lock_guard<std::mutex> lk(gMtx);
        auto rows = query(std::string(REQ_SEL) + "WHERE r.user_id=? ORDER BY r.request_id DESC", s.uid);
        crow::json::wvalue j; j["items"] = crow::json::wvalue::list();
        for (unsigned i = 0; i < rows.size(); i++) reqJson(j["items"][i], rows[i]);
        return crow::response(200, j);
    }));

    // request details + history (student: own only; staff: any)
    CROW_ROUTE(app, "/api/requests/<int>")(safe1([](const crow::request& req, int id) -> crow::response {
        AUTH(s, true);
        std::lock_guard<std::mutex> lk(gMtx);
        auto rows = query(std::string(REQ_SEL) + "WHERE r.request_id=?", id);
        if (rows.empty()) return err(404, "Request not found");
        if (s.role == "student") {
            auto own = query("SELECT 1 FROM requests WHERE request_id=? AND user_id=?", id, s.uid);
            if (own.empty()) return err(403, "Access denied: this request belongs to another student");
        }
        crow::json::wvalue j; reqJson(j, rows[0]); j["history"] = crow::json::wvalue::list();
        auto h = query("SELECT h.old_status,h.new_status,COALESCE(h.remarks,''),h.changed_at,u.name FROM request_history h "
                       "JOIN users u ON u.user_id=h.changed_by WHERE h.request_id=? ORDER BY h.history_id", id);
        for (unsigned i = 0; i < h.size(); i++) {
            j["history"][i]["old_status"] = h[i][0]; j["history"][i]["new_status"] = h[i][1];
            j["history"][i]["remarks"] = h[i][2]; j["history"][i]["changed_at"] = h[i][3]; j["history"][i]["changed_by"] = h[i][4];
        }
        return crow::response(200, j);
    }));

    // -------------------------------------------------------- staff: queue
    CROW_ROUTE(app, "/api/queue")(safe0([](const crow::request& req) -> crow::response {
        AUTH(s, isStaff(s));
        std::lock_guard<std::mutex> lk(gMtx);
        crow::json::wvalue j;
        j["capacity"] = Q->capacity(); j["count"] = Q->size(); j["front"] = Q->front(); j["rear"] = Q->rear();
        j["items"] = crow::json::wvalue::list();
        auto v = Q->display();   // starts at front, exactly count elements
        for (unsigned i = 0; i < v.size(); i++) {
            auto& w = j["items"][i];
            w["array_index"] = Q->physicalIndex((int)i); w["request_id"] = v[i].requestId;
            w["registration_no"] = v[i].regNo; w["category"] = v[i].category;
            w["description"] = v[i].description; w["created_at"] = v[i].createdAt;
        }
        return crow::response(200, j);
    }));

    // Process next: dequeue the FRONT request -> status Processing + assigned operator
    CROW_ROUTE(app, "/api/queue/process").methods("POST"_method)(safe0([](const crow::request& req) -> crow::response {
        AUTH(s, isStaff(s));
        auto b = crow::json::load(req.body);
        std::lock_guard<std::mutex> lk(gMtx);   // two operators can never take the same request
        if (Q->isEmpty()) return err(409, "The pending queue is empty. There is no request to process.");
        int assignee = s.uid;
        if (b && b.has("assign_to") && b["assign_to"].t() == crow::json::type::Number) {
            if (s.role != "administrator") return err(403, "Only administrators can assign requests to another operator");
            int a = (int)b["assign_to"].i();
            if (query("SELECT 1 FROM users WHERE user_id=? AND role IN ('operator','administrator')", a).empty())
                return err(400, "Invalid operator selected");
            assignee = a;
        }
        QueueItem it; Q->peek(it);
        { Tx tx;
          exec("UPDATE requests SET status='Processing',assigned_to=?,updated_at=datetime('now','localtime') "
               "WHERE request_id=? AND status='Pending'", assignee, it.requestId);
          addHistory(it.requestId, s.uid, "Pending", "Processing", "Assigned for processing");
          tx.commit(); }
        QueueItem removed; Q->dequeue(removed);   // only after the DB commit succeeded
        crow::json::wvalue j; j["request_id"] = it.requestId;
        j["message"] = "Request " + std::to_string(it.requestId) + " removed from the queue and assigned for processing";
        return crow::response(200, j);
    }));

    // ------------------------------------------------------ staff: search
    CROW_ROUTE(app, "/api/search")(safe0([](const crow::request& req) -> crow::response {
        AUTH(s, isStaff(s));
        const char* qp = req.url_params.get("q");
        std::string q = qp ? trim(qp) : "";
        if (q.empty()) return err(400, "Enter a request ID or registration number");
        bool digits = q.size() <= 15 && std::all_of(q.begin(), q.end(), ::isdigit);
        long long idv = digits ? std::stoll(q) : -1;
        std::lock_guard<std::mutex> lk(gMtx);
        auto rows = query(std::string(REQ_SEL) + "WHERE r.request_id=? OR u.registration_no=? ORDER BY r.request_id", idv, q);
        if (rows.empty()) return err(404, "No request found for \"" + q + "\"");
        crow::json::wvalue j; j["items"] = crow::json::wvalue::list();
        for (unsigned i = 0; i < rows.size(); i++) reqJson(j["items"][i], rows[i]);
        return crow::response(200, j);
    }));

    // --------------------------------------------------- staff: update status
    CROW_ROUTE(app, "/api/requests/<int>/status").methods("PUT"_method)(safe1([](const crow::request& req, int id) -> crow::response {
        AUTH(s, isStaff(s));
        auto b = crow::json::load(req.body);
        if (!b) return err(400, "Invalid request data");
        std::string ns = jstr(b, "status"), rem = trim(jstr(b, "remarks"));
        if (ns != "Processing" && ns != "Resolved" && ns != "Rejected") return err(400, "Status must be Processing, Resolved or Rejected");
        if (ns == "Rejected" && rem.empty()) return err(400, "Remarks are required when rejecting a request");
        if (rem.size() > 500) return err(400, "Remarks are too long (max 500 characters)");
        std::lock_guard<std::mutex> lk(gMtx);
        auto r = query("SELECT status,COALESCE(assigned_to,0) FROM requests WHERE request_id=?", id);
        if (r.empty()) return err(404, "Request not found");
        std::string cur = r[0][0]; long long as = std::stoll(r[0][1]);
        if (cur == "Pending") return err(409, "This request is still pending. Use \"Process Next\" to take it from the queue first.");
        if (cur == "Resolved" || cur == "Rejected") return err(409, "This request is already closed (" + cur + ")");
        if (cur == ns) return err(409, "The request is already " + ns);
        if (s.role == "operator" && as != s.uid) return err(403, "This request is assigned to another operator");
        { Tx tx;
          exec("UPDATE requests SET status=?,updated_at=datetime('now','localtime') WHERE request_id=?", ns, id);
          addHistory(id, s.uid, cur, ns, rem);
          tx.commit(); }
        crow::json::wvalue j; j["message"] = "Request " + std::to_string(id) + " updated to " + ns;
        return crow::response(200, j);
    }));

    // ---------------------------------------------------- staff: stats/reports
    CROW_ROUTE(app, "/api/stats")(safe0([](const crow::request& req) -> crow::response {
        AUTH(s, isStaff(s));
        std::lock_guard<std::mutex> lk(gMtx);
        crow::json::wvalue j; statsJson(j); return crow::response(200, j);
    }));
    CROW_ROUTE(app, "/api/report")(safe0([](const crow::request& req) -> crow::response {
        AUTH(s, s.role == "administrator");
        std::lock_guard<std::mutex> lk(gMtx);
        crow::json::wvalue j; statsJson(j["stats"]);
        j["by_category"] = crow::json::wvalue::list();
        auto c = query("SELECT category,COUNT(*) FROM requests GROUP BY category ORDER BY category");
        for (unsigned i = 0; i < c.size(); i++) { j["by_category"][i]["category"] = c[i][0]; j["by_category"][i]["count"] = std::stoll(c[i][1]); }
        j["history"] = crow::json::wvalue::list();
        auto h = query("SELECT h.request_id,u.name,COALESCE(h.old_status,''),h.new_status,COALESCE(h.remarks,''),h.changed_at "
                       "FROM request_history h JOIN users u ON u.user_id=h.changed_by ORDER BY h.history_id DESC LIMIT 100");
        for (unsigned i = 0; i < h.size(); i++) {
            auto& w = j["history"][i];
            w["request_id"] = std::stoll(h[i][0]); w["changed_by"] = h[i][1]; w["old_status"] = h[i][2];
            w["new_status"] = h[i][3]; w["remarks"] = h[i][4]; w["changed_at"] = h[i][5];
        }
        return crow::response(200, j);
    }));
    CROW_ROUTE(app, "/api/operators")(safe0([](const crow::request& req) -> crow::response {
        AUTH(s, s.role == "administrator");
        std::lock_guard<std::mutex> lk(gMtx);
        auto o = query("SELECT user_id,name FROM users WHERE role IN ('operator','administrator') ORDER BY name");
        crow::json::wvalue j; j["items"] = crow::json::wvalue::list();
        for (unsigned i = 0; i < o.size(); i++) { j["items"][i]["user_id"] = std::stoll(o[i][0]); j["items"][i]["name"] = o[i][1]; }
        return crow::response(200, j);
    }));

    std::cout << "Help desk server listening on 0.0.0.0:" << port << "\n";
    app.bindaddr("0.0.0.0").port(port).multithreaded().run();   // reachable from other LAN computers
    return 0;
}
