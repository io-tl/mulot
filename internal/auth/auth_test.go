package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chromedp/chromedp"
)

// loginServer simulates three outcomes:
//   - admin/secret  → sets a session cookie, redirects to /dashboard (has logout)
//   - user "nodb"   → redirects to /setup (neutral page, no session, no logout) —
//     this is the DVWA-with-no-database case that used to be a false positive
//   - anything else → re-renders /login with a "Login failed" message
func loginServer() *httptest.Server {
	mux := http.NewServeMux()

	loginPage := `<!doctype html><html><body><form method="post" action="/login">
		<input type="text" name="username">
		<input type="password" name="password">
		<input type="hidden" name="user_token" value="tok123">
		<input type="submit" name="Login" value="Login">
	</form>%s</body></html>`

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			u, p := r.FormValue("username"), r.FormValue("password")
			switch {
			case u == "admin" && p == "secret":
				http.SetCookie(w, &http.Cookie{Name: "SESSION", Value: "abc123", Path: "/", HttpOnly: true})
				http.Redirect(w, r, "/dashboard", http.StatusFound)
			case u == "nodb":
				http.Redirect(w, r, "/setup", http.StatusFound)
			default:
				w.Write([]byte("<!doctype html><html><body>" +
					"<form method=post action=/login><input type=password name=password></form>" +
					"<p class=error>Login failed</p></body></html>"))
			}
			return
		}
		w.Write([]byte("<!doctype html><html><body>" + loginPage[:len(loginPage)-2] + "</body></html>"))
	})

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<!doctype html><html><body><h1>Welcome admin</h1>
			<a href="/logout">Logout</a></body></html>`))
	})
	mux.HandleFunc("/setup", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<!doctype html><html><body><h1>Database Setup</h1>
			<button>Create / Reset Database</button></body></html>`))
	})

	return httptest.NewServer(mux)
}

func tab(t *testing.T) (context.Context, func()) {
	t.Helper()
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
		)...)
	ctx, ctxCancel := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(ctx); err != nil {
		ctxCancel()
		allocCancel()
		t.Fatalf("chromium unavailable: %v", err)
	}
	return ctx, func() { ctxCancel(); allocCancel() }
}

func baseParams(url string) LoginParams {
	return LoginParams{
		URL:              url + "/login",
		UsernameSelector: `input[name="username"]`,
		PasswordSelector: `input[name="password"]`,
		SubmitSelector:   `input[type="submit"]`,
		IsolateSession:   true,
	}
}

func TestLoginValid(t *testing.T) {
	srv := loginServer()
	defer srv.Close()
	ctx, cancel := tab(t)
	defer cancel()

	p := baseParams(srv.URL)
	p.Username, p.Password = "admin", "secret"

	res, err := TestLogin(ctx, p)
	if err != nil {
		t.Fatalf("TestLogin: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success, got false (reason=%q, finalUrl=%q)", res.Reason, res.FinalURL)
	}
	if res.Confidence != "high" {
		t.Errorf("expected high confidence, got %q", res.Confidence)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	srv := loginServer()
	defer srv.Close()
	ctx, cancel := tab(t)
	defer cancel()

	p := baseParams(srv.URL)
	p.Username, p.Password = "admin", "wrongpass"

	res, err := TestLogin(ctx, p)
	if err != nil {
		t.Fatalf("TestLogin: %v", err)
	}
	if res.Success {
		t.Errorf("expected failure for wrong password, got success (reason=%q)", res.Reason)
	}
}

// TestLoginRedirectToNeutralPage is the regression test for the reported bug:
// a failed login that redirects to a non-login page (DVWA → setup.php) must NOT
// be reported as success.
func TestLoginRedirectToNeutralPage(t *testing.T) {
	srv := loginServer()
	defer srv.Close()
	ctx, cancel := tab(t)
	defer cancel()

	p := baseParams(srv.URL)
	p.Username, p.Password = "nodb", "whatever"

	res, err := TestLogin(ctx, p)
	if err != nil {
		t.Fatalf("TestLogin: %v", err)
	}
	if res.Success {
		t.Errorf("redirect to neutral page must NOT be success (finalUrl=%q, reason=%q)", res.FinalURL, res.Reason)
	}
	if res.Confidence != "low" {
		t.Errorf("expected low confidence (indeterminate), got %q", res.Confidence)
	}
}
