package js

import (
	"context"
	"fmt"
	"sync"

	cdpRuntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

type ConsoleEntry struct {
	Level  string `json:"level"`
	Text   string `json:"text"`
	URL    string `json:"url,omitempty"`
	Line   int64  `json:"line,omitempty"`
	Column int64  `json:"column,omitempty"`
}

type JSError struct {
	Message    string `json:"message"`
	URL        string `json:"url,omitempty"`
	Line       int64  `json:"line,omitempty"`
	Column     int64  `json:"column,omitempty"`
	StackTrace string `json:"stackTrace,omitempty"`
}

type ConsoleCapture struct {
	mu      sync.Mutex
	entries []ConsoleEntry
	errors  []JSError
	active  bool
}

func NewConsoleCapture() *ConsoleCapture {
	return &ConsoleCapture{active: true}
}

func (c *ConsoleCapture) Start(ctx context.Context) error {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.active {
			return
		}

		switch e := ev.(type) {
		case *cdpRuntime.EventConsoleAPICalled:
			text := ""
			for _, arg := range e.Args {
				if arg.Value != nil {
					text += fmt.Sprintf("%s ", string(arg.Value))
				} else if arg.UnserializableValue != "" {
					text += fmt.Sprintf("%s ", string(arg.UnserializableValue))
				} else if arg.Description != "" {
					text += fmt.Sprintf("%s ", arg.Description)
				}
			}
			entry := ConsoleEntry{
				Level: string(e.Type),
				Text:  text,
			}
			if e.StackTrace != nil && len(e.StackTrace.CallFrames) > 0 {
				entry.URL = e.StackTrace.CallFrames[0].URL
				entry.Line = e.StackTrace.CallFrames[0].LineNumber
				entry.Column = e.StackTrace.CallFrames[0].ColumnNumber
			}
			c.entries = append(c.entries, entry)

		case *cdpRuntime.EventExceptionThrown:
			jsErr := JSError{}
			if e.ExceptionDetails != nil {
				if e.ExceptionDetails.Exception != nil {
					jsErr.Message = e.ExceptionDetails.Exception.Description
				}
				if jsErr.Message == "" {
					jsErr.Message = e.ExceptionDetails.Text
				}
				jsErr.URL = e.ExceptionDetails.URL
				jsErr.Line = e.ExceptionDetails.LineNumber
				jsErr.Column = e.ExceptionDetails.ColumnNumber
				if e.ExceptionDetails.StackTrace != nil {
					for _, f := range e.ExceptionDetails.StackTrace.CallFrames {
						jsErr.StackTrace += fmt.Sprintf("  at %s (%s:%d:%d)\n",
							f.FunctionName, f.URL, f.LineNumber, f.ColumnNumber)
					}
				}
			}
			c.errors = append(c.errors, jsErr)
		}
	})

	return chromedp.Run(ctx, cdpRuntime.Enable())
}

func (c *ConsoleCapture) GetEntries() []ConsoleEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]ConsoleEntry, len(c.entries))
	copy(result, c.entries)
	return result
}

func (c *ConsoleCapture) GetErrors() []JSError {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]JSError, len(c.errors))
	copy(result, c.errors)
	return result
}

func (c *ConsoleCapture) GetEntriesByLevel(level string) []ConsoleEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []ConsoleEntry
	for _, e := range c.entries {
		if e.Level == level {
			result = append(result, e)
		}
	}
	return result
}

func (c *ConsoleCapture) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
	c.errors = nil
}

func (c *ConsoleCapture) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = false
}

// awaitPromise makes chromedp await a returned Promise and hand back its
// resolved value. It is a no-op for non-Promise expressions, so it is safe to
// always apply — and it is what lets an in-page async fetch loop (concurrent
// fuzzing/brute-force, returning only the hits) run in a single evaluate call.
func awaitPromise(p *cdpRuntime.EvaluateParams) *cdpRuntime.EvaluateParams {
	return p.WithAwaitPromise(true)
}

func Evaluate(ctx context.Context, expression string) (interface{}, error) {
	var result interface{}
	if err := chromedp.Run(ctx, chromedp.Evaluate(expression, &result, awaitPromise)); err != nil {
		return nil, err
	}
	return result, nil
}

func EvaluateAsString(ctx context.Context, expression string) (string, error) {
	var result string
	if err := chromedp.Run(ctx, chromedp.Evaluate(expression, &result)); err != nil {
		return "", err
	}
	return result, nil
}
