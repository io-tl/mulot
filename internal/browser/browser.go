package browser

import (
	"context"
	"sync"

	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/internal/envcfg"
)

type Browser struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	mu          sync.Mutex
	tabs        []*Tab
	opts        Options
}

type Tab struct {
	ctx    context.Context
	cancel context.CancelFunc
	id     int
}

type Options struct {
	Headless   bool
	WindowSize [2]int
	ProxyURL   string
	UserAgent  string
}

type Option func(*Options)

func WithHeadless(h bool) Option {
	return func(o *Options) { o.Headless = h }
}

func WithProxy(url string) Option {
	return func(o *Options) { o.ProxyURL = url }
}

func WithWindowSize(w, h int) Option {
	return func(o *Options) { o.WindowSize = [2]int{w, h} }
}

func WithUserAgent(ua string) Option {
	return func(o *Options) { o.UserAgent = ua }
}

func New(opts ...Option) *Browser {
	o := Options{
		Headless:   envcfg.Headless(true),
		WindowSize: [2]int{1280, 720},
		UserAgent:  envcfg.UserAgent(),
		ProxyURL:   envcfg.ProxyURL(),
	}
	for _, fn := range opts {
		fn(&o)
	}
	return &Browser{opts: o}
}

func (b *Browser) Start(_ context.Context) error {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", b.opts.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.WindowSize(b.opts.WindowSize[0], b.opts.WindowSize[1]),
		// Targets routinely present self-signed/expired/mismatched certs (or sit
		// behind an intercepting proxy re-signing traffic); don't let that block
		// navigation.
		chromedp.IgnoreCertErrors,
	)

	if b.opts.ProxyURL != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(b.opts.ProxyURL))
	}
	if b.opts.UserAgent != "" {
		allocOpts = append(allocOpts, chromedp.UserAgent(b.opts.UserAgent))
	}

	b.allocCtx, b.allocCancel = chromedp.NewExecAllocator(context.Background(), allocOpts...)
	return nil
}

var tabCounter int
var tabCounterMu sync.Mutex

func (b *Browser) NewTab(ctx context.Context) (*Tab, error) {
	tabCtx, cancel := chromedp.NewContext(b.allocCtx)
	if err := chromedp.Run(tabCtx); err != nil {
		cancel()
		return nil, err
	}

	tabCounterMu.Lock()
	tabCounter++
	id := tabCounter
	tabCounterMu.Unlock()

	t := &Tab{ctx: tabCtx, cancel: cancel, id: id}

	b.mu.Lock()
	b.tabs = append(b.tabs, t)
	b.mu.Unlock()

	return t, nil
}

func (b *Browser) Close() error {
	b.mu.Lock()
	tabs := make([]*Tab, len(b.tabs))
	copy(tabs, b.tabs)
	b.tabs = nil
	b.mu.Unlock()

	for _, t := range tabs {
		t.Close()
	}

	if b.allocCancel != nil {
		b.allocCancel()
	}
	return nil
}

func (t *Tab) Context() context.Context {
	return t.ctx
}

func (t *Tab) ID() int {
	return t.id
}

func (t *Tab) Close() {
	if t.cancel != nil {
		t.cancel()
	}
}

func (t *Tab) Run(actions ...chromedp.Action) error {
	return chromedp.Run(t.ctx, actions...)
}
