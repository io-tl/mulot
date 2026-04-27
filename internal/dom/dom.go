package dom

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/chromedp/chromedp"
)

type Element struct {
	TagName     string            `json:"tagName"`
	ID          string            `json:"id,omitempty"`
	Classes     []string          `json:"classes,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	TextContent string            `json:"textContent,omitempty"`
	InnerHTML   string            `json:"innerHTML,omitempty"`
	Visible     bool              `json:"visible"`
	BoundingBox *Rect             `json:"boundingBox,omitempty"`
}

type Rect struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type FormField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	ID          string `json:"id,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Value       string `json:"value,omitempty"`
	Required    bool   `json:"required"`
	Selector    string `json:"selector"`
}

// Interactive is one actionable element of a page snapshot. Ref is a short
// stable handle (e.g. "e7") that browser_click / browser_type accept directly,
// so the agent never needs a separate browser_query_dom round-trip.
type Interactive struct {
	Ref     string `json:"ref"`
	Role    string `json:"role"`
	Name    string `json:"name,omitempty"`
	Value   string `json:"value,omitempty"`
	Type    string `json:"type,omitempty"`
	Visible bool   `json:"visible"`
}

// RefAttr is the DOM attribute used to address snapshot elements.
const RefAttr = "data-mulot-ref"

// RefSelector turns a snapshot ref ("e7") into the CSS selector that targets it.
func RefSelector(ref string) string {
	return `[` + RefAttr + `="` + ref + `"]`
}

// GetInteractive walks the live DOM, tags every interactive element (and
// headings, for context) with a stable data-mulot-ref attribute, and returns a
// compact, directly-actionable list. The accessible name is computed in-page
// (aria-label > aria-labelledby > associated <label> > placeholder > alt >
// button value > visible text > title), which also normalizes whitespace and
// avoids the unicode double-escaping of the raw CDP accessibility tree.
func GetInteractive(ctx context.Context, limit int) ([]Interactive, bool, error) {
	var resultJSON string
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(buildInteractiveScript(limit), &resultJSON),
	); err != nil {
		return nil, false, err
	}
	var payload struct {
		Elements  []Interactive `json:"elements"`
		Truncated bool          `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &payload); err != nil {
		return nil, false, err
	}
	return payload.Elements, payload.Truncated, nil
}

func Query(ctx context.Context, selector string) ([]Element, error) {
	var resultJSON string
	err := chromedp.Run(ctx,
		chromedp.Evaluate(buildQueryScript(selector), &resultJSON),
	)
	if err != nil {
		return nil, err
	}
	var elements []Element
	if err := json.Unmarshal([]byte(resultJSON), &elements); err != nil {
		return nil, err
	}
	return elements, nil
}

func QueryOne(ctx context.Context, selector string) (*Element, error) {
	elements, err := Query(ctx, selector)
	if err != nil {
		return nil, err
	}
	if len(elements) == 0 {
		return nil, nil
	}
	return &elements[0], nil
}

// ClearField empties an input/textarea reliably, including when it is already
// empty (chromedp.Clear errors on a field with no text node) and when the field
// is React/Vue-controlled (uses the native value setter so the framework's
// onChange fires). Returns an error if the selector matches nothing.
func ClearField(ctx context.Context, selector string) error {
	var result string
	script := `(function(){
		var el = document.querySelector(` + jsonString(selector) + `);
		if (!el) return 'not_found';
		var proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
		var desc = Object.getOwnPropertyDescriptor(proto, 'value');
		if (desc && desc.set) { desc.set.call(el, ''); } else { el.value = ''; }
		el.dispatchEvent(new Event('input', {bubbles: true}));
		el.dispatchEvent(new Event('change', {bubbles: true}));
		return 'ok';
	})()`
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &result)); err != nil {
		return err
	}
	if result == "not_found" {
		return errNotFound(selector)
	}
	return nil
}

// SelectOption sets a <select> to the option whose value OR visible text equals
// value, dispatching input/change so listeners fire. The agent never needs
// evaluate_js for dropdowns.
func SelectOption(ctx context.Context, selector, value string) error {
	var result string
	script := `(function(){
		var el = document.querySelector(` + jsonString(selector) + `);
		if (!el) return 'not_found';
		if (el.tagName !== 'SELECT') return 'not_select';
		var want = ` + jsonString(value) + `;
		var opt = null;
		for (var i = 0; i < el.options.length; i++) {
			var o = el.options[i];
			if (o.value === want || o.text.trim() === want) { opt = o; break; }
		}
		if (!opt) return 'no_option';
		el.value = opt.value;
		el.dispatchEvent(new Event('input', {bubbles: true}));
		el.dispatchEvent(new Event('change', {bubbles: true}));
		return 'ok';
	})()`
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &result)); err != nil {
		return err
	}
	switch result {
	case "not_found":
		return errNotFound(selector)
	case "not_select":
		return fmt.Errorf("element %q is not a <select>", selector)
	case "no_option":
		return fmt.Errorf("no <option> with value or label %q in %q", value, selector)
	}
	return nil
}

func errNotFound(selector string) error {
	return fmt.Errorf("no element matches selector %q", selector)
}

func GetFormFields(ctx context.Context, formSelector string) ([]FormField, error) {
	var resultJSON string
	err := chromedp.Run(ctx,
		chromedp.Evaluate(buildFormFieldsScript(formSelector), &resultJSON),
	)
	if err != nil {
		return nil, err
	}
	var fields []FormField
	if err := json.Unmarshal([]byte(resultJSON), &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

func GetOuterHTML(ctx context.Context, selector string) (string, error) {
	var html string
	if err := chromedp.Run(ctx, chromedp.OuterHTML(selector, &html)); err != nil {
		return "", err
	}
	return html, nil
}

func buildQueryScript(selector string) string {
	return `(function() {
		var els = document.querySelectorAll(` + jsonString(selector) + `);
		var result = [];
		els.forEach(function(el) {
			var rect = el.getBoundingClientRect();
			var attrs = {};
			for (var i = 0; i < el.attributes.length; i++) {
				attrs[el.attributes[i].name] = el.attributes[i].value;
			}
			result.push({
				tagName: el.tagName.toLowerCase(),
				id: el.id || '',
				classes: Array.from(el.classList),
				attributes: attrs,
				textContent: (el.textContent || '').trim().substring(0, 500),
				innerHTML: el.innerHTML.substring(0, 1000),
				visible: rect.width > 0 && rect.height > 0 && getComputedStyle(el).visibility !== 'hidden',
				boundingBox: {x: rect.x, y: rect.y, width: rect.width, height: rect.height}
			});
		});
		return JSON.stringify(result);
	})()`
}

func buildFormFieldsScript(formSelector string) string {
	return `(function() {
		var form = document.querySelector(` + jsonString(formSelector) + `);
		if (!form) return JSON.stringify([]);
		var inputs = form.querySelectorAll('input, select, textarea');
		var fields = [];
		inputs.forEach(function(el, i) {
			var selector = el.id ? '#' + el.id : (el.name ? '[name="' + el.name + '"]' : el.tagName.toLowerCase() + ':nth-child(' + (i+1) + ')');
			fields.push({
				name: el.name || '',
				type: el.type || el.tagName.toLowerCase(),
				id: el.id || '',
				placeholder: el.placeholder || '',
				value: el.value || '',
				required: el.required || false,
				selector: selector
			});
		});
		return JSON.stringify(fields);
	})()`
}

func buildInteractiveScript(limit int) string {
	if limit <= 0 {
		limit = 200
	}
	return `(function() {
		var LIMIT = ` + itoa(limit) + `;
		var SEL = 'a[href], button, input:not([type="hidden"]), select, textarea, summary, ' +
			'[role], [onclick], [tabindex]:not([tabindex="-1"]), [contenteditable="true"], ' +
			'h1, h2, h3, h4, h5, h6';

		function visible(el) {
			var r = el.getBoundingClientRect();
			if (r.width <= 0 || r.height <= 0) return false;
			var st = getComputedStyle(el);
			return st.visibility !== 'hidden' && st.display !== 'none' && st.opacity !== '0';
		}

		function role(el) {
			var r = el.getAttribute('role');
			if (r) return r.trim().split(/\s+/)[0];
			var tag = el.tagName.toLowerCase();
			if (tag === 'a') return el.getAttribute('href') ? 'link' : 'generic';
			if (tag === 'button' || tag === 'summary') return 'button';
			if (tag === 'select') return 'combobox';
			if (tag === 'textarea') return 'textbox';
			if (tag === 'input') {
				var t = (el.getAttribute('type') || 'text').toLowerCase();
				if (t === 'checkbox') return 'checkbox';
				if (t === 'radio') return 'radio';
				if (t === 'submit' || t === 'button' || t === 'reset' || t === 'image') return 'button';
				if (t === 'range') return 'slider';
				return 'textbox';
			}
			if (/^h[1-6]$/.test(tag)) return 'heading';
			return tag;
		}

		function clean(s) { return (s || '').replace(/\s+/g, ' ').trim().substring(0, 200); }

		function accName(el) {
			var al = el.getAttribute('aria-label');
			if (al && al.trim()) return clean(al);
			var lb = el.getAttribute('aria-labelledby');
			if (lb) {
				var t = lb.split(/\s+/).map(function(id) {
					var e = document.getElementById(id);
					return e ? e.innerText : '';
				}).join(' ');
				if (t.trim()) return clean(t);
			}
			if (el.labels && el.labels.length) {
				var lt = Array.prototype.map.call(el.labels, function(l) { return l.innerText; }).join(' ');
				if (lt.trim()) return clean(lt);
			}
			if (el.placeholder) return clean(el.placeholder);
			var alt = el.getAttribute('alt');
			if (alt && alt.trim()) return clean(alt);
			if (el.tagName === 'INPUT') {
				var ty = (el.getAttribute('type') || '').toLowerCase();
				if ((ty === 'submit' || ty === 'button' || ty === 'reset') && el.value) return clean(el.value);
			}
			var txt = el.innerText || el.textContent || '';
			if (txt.trim()) return clean(txt);
			var title = el.getAttribute('title');
			if (title && title.trim()) return clean(title);
			return '';
		}

		var els = document.querySelectorAll(SEL);
		var out = [];
		var n = 0;
		var truncated = false;
		for (var i = 0; i < els.length; i++) {
			var el = els[i];
			if (!visible(el)) continue;
			if (n >= LIMIT) { truncated = true; break; }
			var ref = 'e' + n;
			el.setAttribute('data-mulot-ref', ref);
			var item = { ref: ref, role: role(el), name: accName(el), visible: true };
			if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') {
				item.type = (el.getAttribute('type') || el.tagName.toLowerCase());
				if (el.value) item.value = String(el.value).substring(0, 100);
			}
			out.push(item);
			n++;
		}
		return JSON.stringify({ elements: out, truncated: truncated });
	})()`
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
