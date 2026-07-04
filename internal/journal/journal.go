// Package journal records every HTTP exchange the browser makes into a local
// SQLite database, so the agent has a persistent, queryable audit trail it can
// filter, inspect, and replay. CDP sees decrypted HTTPS, so no MITM proxy is
// needed. Hot metadata (flows) is kept separate from cold bodies for fast
// listing; headers are stored as JSON and remain queryable via SQLite JSON1.
package journal

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cdpNetwork "github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	_ "modernc.org/sqlite"
)

const maxBody = 1 << 20 // 1 MiB cap per stored body

const schema = `
CREATE TABLE IF NOT EXISTS flows (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id     TEXT,
  started_at     INTEGER NOT NULL,
  method         TEXT NOT NULL,
  url            TEXT NOT NULL,
  scheme         TEXT,
  host           TEXT,
  path           TEXT,
  query          TEXT,
  req_headers    TEXT,
  req_body_size  INTEGER DEFAULT 0,
  status         INTEGER DEFAULT 0,
  status_text    TEXT,
  mime_type      TEXT,
  resp_headers   TEXT,
  resp_body_size INTEGER DEFAULT 0,
  duration_ms    INTEGER DEFAULT 0,
  failed         INTEGER DEFAULT 0,
  error          TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_host    ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_status  ON flows(status);
CREATE INDEX IF NOT EXISTS idx_flows_started ON flows(started_at);

CREATE TABLE IF NOT EXISTS bodies (
  flow_id   INTEGER NOT NULL,
  kind      TEXT NOT NULL,
  content   BLOB,
  size      INTEGER,
  truncated INTEGER DEFAULT 0,
  PRIMARY KEY (flow_id, kind)
);

CREATE TABLE IF NOT EXISTS findings (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  content    TEXT NOT NULL
);`

type pending struct {
	requestID    string
	startedAt    int64
	method       string
	url          string
	reqHeaders   map[string]string
	reqBody      string
	status       int64
	statusText   string
	mimeType     string
	respHeaders  map[string]string
	respBodySize int64
	failed       bool
	errText      string
}

type Journal struct {
	db      *sql.DB
	path    string
	mu      sync.Mutex
	pending map[string]*pending
	queue   chan string
	done    chan struct{}
	closed  bool
	ctx     context.Context
	wg      sync.WaitGroup
	started bool
}

// Open opens (creating if needed) the SQLite journal at path. An empty path
// defaults to ~/.mulot/traffic.db.
func Open(path string) (*Journal, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = os.TempDir()
		}
		dir := filepath.Join(home, ".mulot")
		os.MkdirAll(dir, 0o755)
		path = filepath.Join(dir, "traffic.db")
	} else {
		os.MkdirAll(filepath.Dir(path), 0o755)
	}

	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // serialize writes/reads on a single connection
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Journal{
		db:      db,
		path:    path,
		pending: make(map[string]*pending),
		queue:   make(chan string, 2048),
		done:    make(chan struct{}),
	}, nil
}

func (j *Journal) Path() string { return j.path }

// Start attaches the CDP listener (on the tab context) and the body-writer
// worker. CDP commands (getResponseBody) must run off the ListenTarget
// callback, so finished requests are queued and drained by the worker.
func (j *Journal) Start(ctx context.Context) {
	j.mu.Lock()
	if j.started {
		j.mu.Unlock()
		return
	}
	j.started = true
	j.ctx = ctx
	j.mu.Unlock()

	chromedp.ListenTarget(ctx, func(ev any) {
		switch e := ev.(type) {
		case *cdpNetwork.EventRequestWillBeSent:
			reqID := string(e.RequestID)
			// A redirect reuses the request id: the prior hop's 3xx response is
			// delivered here as RedirectResponse (CDP never fires a separate
			// responseReceived for it). Record that hop as its own flow so its
			// headers — Location, Set-Cookie — are kept and queryable.
			if e.RedirectResponse != nil {
				j.mu.Lock()
				prev, ok := j.pending[reqID]
				if ok {
					delete(j.pending, reqID)
				}
				j.mu.Unlock()
				if ok {
					prev.status = e.RedirectResponse.Status
					prev.statusText = e.RedirectResponse.StatusText
					prev.mimeType = e.RedirectResponse.MimeType
					prev.respHeaders = headerMap(e.RedirectResponse.Headers)
					j.writeFlow(prev, nil, false) // redirect hop: no body to fetch
				}
			}
			p := &pending{
				requestID:  reqID,
				startedAt:  time.Now().UnixMilli(),
				method:     e.Request.Method,
				url:        e.Request.URL,
				reqHeaders: headerMap(e.Request.Headers),
			}
			if e.Request.HasPostData {
				for _, pde := range e.Request.PostDataEntries {
					p.reqBody += decodeMaybe(pde.Bytes)
				}
			}
			j.mu.Lock()
			j.pending[reqID] = p
			j.mu.Unlock()

		case *cdpNetwork.EventResponseReceived:
			j.mu.Lock()
			if p, ok := j.pending[string(e.RequestID)]; ok {
				p.status = e.Response.Status
				p.statusText = e.Response.StatusText
				p.mimeType = e.Response.MimeType
				p.respHeaders = headerMap(e.Response.Headers)
			}
			j.mu.Unlock()

		case *cdpNetwork.EventLoadingFinished:
			j.mu.Lock()
			if p, ok := j.pending[string(e.RequestID)]; ok {
				p.respBodySize = int64(e.EncodedDataLength)
			}
			j.mu.Unlock()
			j.enqueue(string(e.RequestID))

		case *cdpNetwork.EventLoadingFailed:
			j.mu.Lock()
			if p, ok := j.pending[string(e.RequestID)]; ok {
				p.failed = true
				p.errText = e.ErrorText
			}
			j.mu.Unlock()
			j.enqueue(string(e.RequestID))
		}
	})

	j.wg.Add(1)
	go j.worker()
}

func (j *Journal) enqueue(id string) {
	j.mu.Lock()
	closed := j.closed
	j.mu.Unlock()
	if closed {
		return
	}
	select {
	case j.queue <- id:
	default: // queue full — drop, best effort
	}
}

func (j *Journal) worker() {
	defer j.wg.Done()
	for {
		select {
		case <-j.done:
			// Drain whatever is already queued, then stop.
			for {
				select {
				case id := <-j.queue:
					j.finalize(id)
				default:
					return
				}
			}
		case id := <-j.queue:
			j.finalize(id)
		}
	}
}

func (j *Journal) finalize(id string) {
	j.mu.Lock()
	p, ok := j.pending[id]
	if ok {
		delete(j.pending, id)
	}
	j.mu.Unlock()
	if !ok {
		return
	}

	var respBody []byte
	var respTrunc bool
	if !p.failed && isTextMime(p.mimeType) {
		respBody, respTrunc = j.fetchBody(id)
	}
	j.writeFlow(p, respBody, respTrunc)
}

func (j *Journal) fetchBody(id string) ([]byte, bool) {
	if j.ctx == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(j.ctx, 3*time.Second)
	defer cancel()
	var body []byte
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var e error
		body, e = cdpNetwork.GetResponseBody(cdpNetwork.RequestID(id)).Do(ctx)
		return e
	}))
	if err != nil {
		return nil, false
	}
	if len(body) > maxBody {
		return body[:maxBody], true
	}
	return body, false
}

func (j *Journal) writeFlow(p *pending, respBody []byte, respTrunc bool) {
	scheme, host, path, query := splitURL(p.url)
	reqH, _ := json.Marshal(p.reqHeaders)
	respH, _ := json.Marshal(p.respHeaders)
	duration := time.Now().UnixMilli() - p.startedAt

	res, err := j.db.Exec(`INSERT INTO flows
		(request_id, started_at, method, url, scheme, host, path, query,
		 req_headers, req_body_size, status, status_text, mime_type,
		 resp_headers, resp_body_size, duration_ms, failed, error)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.requestID, p.startedAt, p.method, p.url, scheme, host, path, query,
		string(reqH), len(p.reqBody), p.status, p.statusText, p.mimeType,
		string(respH), p.respBodySize, duration, b2i(p.failed), p.errText)
	if err != nil {
		return
	}
	flowID, _ := res.LastInsertId()

	if len(p.reqBody) > 0 {
		body := []byte(p.reqBody)
		trunc := false
		if len(body) > maxBody {
			body = body[:maxBody]
			trunc = true
		}
		j.db.Exec(`INSERT INTO bodies (flow_id, kind, content, size, truncated) VALUES (?,?,?,?,?)`,
			flowID, "request", body, len(p.reqBody), b2i(trunc))
	}
	if respBody != nil {
		j.db.Exec(`INSERT INTO bodies (flow_id, kind, content, size, truncated) VALUES (?,?,?,?,?)`,
			flowID, "response", respBody, len(respBody), b2i(respTrunc))
	}
}

// Close stops capture, drains pending writes, and closes the database.
func (j *Journal) Close() error {
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return nil
	}
	j.closed = true
	j.mu.Unlock()
	if j.started {
		close(j.done)
		j.wg.Wait()
	}
	return j.db.Close()
}

// ── Query API ──────────────────────────────────────────────

type Filter struct {
	Host         string
	Method       string
	Status       int
	StatusMin    int
	URLContains  string
	BodyContains string
	SinceID      int64
	Limit        int
}

type FlowRow struct {
	ID           int64  `json:"id"`
	StartedAt    int64  `json:"startedAt"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	Host         string `json:"host"`
	Status       int    `json:"status"`
	StatusText   string `json:"statusText,omitempty"`
	MimeType     string `json:"mimeType,omitempty"`
	RespBodySize int64  `json:"respBodySize"`
	DurationMs   int64  `json:"durationMs"`
	Failed       bool   `json:"failed,omitempty"`
	Error        string `json:"error,omitempty"`
}

func (j *Journal) Query(f Filter) ([]FlowRow, error) {
	var where []string
	var args []any
	if f.Host != "" {
		where = append(where, "host = ?")
		args = append(args, f.Host)
	}
	if f.Method != "" {
		where = append(where, "method = ?")
		args = append(args, strings.ToUpper(f.Method))
	}
	if f.Status != 0 {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.StatusMin != 0 {
		where = append(where, "status >= ?")
		args = append(args, f.StatusMin)
	}
	if f.URLContains != "" {
		where = append(where, "url LIKE ?")
		args = append(args, "%"+f.URLContains+"%")
	}
	if f.SinceID != 0 {
		where = append(where, "id > ?")
		args = append(args, f.SinceID)
	}
	if f.BodyContains != "" {
		where = append(where, "EXISTS (SELECT 1 FROM bodies b WHERE b.flow_id = flows.id AND CAST(b.content AS TEXT) LIKE ?)")
		args = append(args, "%"+f.BodyContains+"%")
	}

	q := `SELECT id, started_at, method, url, host, status, status_text,
		mime_type, resp_body_size, duration_ms, failed, error FROM flows`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := j.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FlowRow
	for rows.Next() {
		var r FlowRow
		var failed int
		if err := rows.Scan(&r.ID, &r.StartedAt, &r.Method, &r.URL, &r.Host,
			&r.Status, &r.StatusText, &r.MimeType, &r.RespBodySize,
			&r.DurationMs, &failed, &r.Error); err != nil {
			return nil, err
		}
		r.Failed = failed != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// Body returns a stored request/response body and whether it was truncated.
func (j *Journal) Body(flowID int64, kind string) ([]byte, bool, error) {
	var content []byte
	var truncated int
	err := j.db.QueryRow(`SELECT content, truncated FROM bodies WHERE flow_id = ? AND kind = ?`,
		flowID, kind).Scan(&content, &truncated)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return content, truncated != 0, nil
}

// FlowDetail is a single exchange with its headers — used to read response
// headers the browser saw (Location on a redirect, Set-Cookie, WWW-Authenticate,
// CSP, custom headers) without re-issuing the request.
type FlowDetail struct {
	ID          int64             `json:"id"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	StatusText  string            `json:"statusText,omitempty"`
	MimeType    string            `json:"mimeType,omitempty"`
	ReqHeaders  map[string]string `json:"requestHeaders"`
	RespHeaders map[string]string `json:"responseHeaders"`
}

func (j *Journal) Flow(id int64) (*FlowDetail, error) {
	var d FlowDetail
	var rq, rs string
	err := j.db.QueryRow(`SELECT id, method, url, status, status_text, mime_type, req_headers, resp_headers FROM flows WHERE id = ?`, id).
		Scan(&d.ID, &d.Method, &d.URL, &d.Status, &d.StatusText, &d.MimeType, &rq, &rs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(rq), &d.ReqHeaders)
	json.Unmarshal([]byte(rs), &d.RespHeaders)
	return &d, nil
}

// ResponseView is a flattened response for passive scanning: URL, status, mime
// type, response headers (original CDP casing), and the stored response body
// (text-like only; empty otherwise). Built by Responses in a single query.
type ResponseView struct {
	URL         string
	Status      int
	MimeType    string
	RespHeaders map[string]string
	Body        string
}

// Responses returns every flow's response for passive analysis, in capture
// order. One LEFT JOIN against the cold body table, so no N+1 round-trips.
func (j *Journal) Responses() ([]ResponseView, error) {
	rows, err := j.db.Query(`SELECT f.url, f.status, f.mime_type, f.resp_headers, b.content
		FROM flows f LEFT JOIN bodies b ON b.flow_id = f.id AND b.kind = 'response'
		ORDER BY f.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ResponseView
	for rows.Next() {
		var rv ResponseView
		var headersJSON sql.NullString
		var content []byte
		if err := rows.Scan(&rv.URL, &rv.Status, &rv.MimeType, &headersJSON, &content); err != nil {
			return nil, err
		}
		if headersJSON.Valid && headersJSON.String != "" {
			json.Unmarshal([]byte(headersJSON.String), &rv.RespHeaders)
		}
		rv.Body = string(content)
		out = append(out, rv)
	}
	return out, rows.Err()
}

// ReplayData holds what is needed to re-issue a captured request.
type ReplayData struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

func (j *Journal) ForReplay(flowID int64) (*ReplayData, error) {
	var method, rawURL, headersJSON string
	err := j.db.QueryRow(`SELECT method, url, req_headers FROM flows WHERE id = ?`, flowID).
		Scan(&method, &rawURL, &headersJSON)
	if err != nil {
		return nil, err
	}
	rd := &ReplayData{Method: method, URL: rawURL, Headers: map[string]string{}}
	json.Unmarshal([]byte(headersJSON), &rd.Headers)
	if body, _, _ := j.Body(flowID, "request"); body != nil {
		rd.Body = string(body)
	}
	return rd, nil
}

// ── Findings (agent-submitted results) ─────────────────────

// Finding is a result the agent chose to persist (a flag, a proof, a note),
// recorded into the same DB as the traffic so a batch runner can collect it.
type Finding struct {
	ID        int64  `json:"id"`
	CreatedAt int64  `json:"createdAt"`
	Content   string `json:"content"`
}

// AddFinding records an agent-submitted result into the findings table and
// returns its row id.
func (j *Journal) AddFinding(content string) (int64, error) {
	res, err := j.db.Exec(`INSERT INTO findings (created_at, content) VALUES (?, ?)`,
		time.Now().UnixMilli(), content)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Findings returns all recorded findings, oldest first.
func (j *Journal) Findings() ([]Finding, error) {
	rows, err := j.db.Query(`SELECT id, created_at, content FROM findings ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.CreatedAt, &f.Content); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Clear empties the journal.
func (j *Journal) Clear() error {
	if _, err := j.db.Exec(`DELETE FROM bodies`); err != nil {
		return err
	}
	_, err := j.db.Exec(`DELETE FROM flows`)
	return err
}

// ── helpers ────────────────────────────────────────────────

func headerMap(h cdpNetwork.Headers) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		if s, ok := v.(string); ok {
			m[k] = s
		}
	}
	return m
}

func splitURL(raw string) (scheme, host, path, query string) {
	if u, err := url.Parse(raw); err == nil {
		return u.Scheme, u.Hostname(), u.Path, u.RawQuery
	}
	return "", "", "", ""
}

func isTextMime(mime string) bool {
	if mime == "" {
		return true
	}
	m := strings.ToLower(mime)
	for _, t := range []string{"text", "json", "javascript", "xml", "html", "csv", "x-www-form", "ecmascript"} {
		if strings.Contains(m, t) {
			return true
		}
	}
	return false
}

func decodeMaybe(s string) string {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
