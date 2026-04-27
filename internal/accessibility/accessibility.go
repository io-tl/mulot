package accessibility

import (
	"context"
	"strings"

	"github.com/chromedp/cdproto/accessibility"
	"github.com/chromedp/chromedp"
)

type Node struct {
	Role        string  `json:"role"`
	Name        string  `json:"name"`
	Value       string  `json:"value,omitempty"`
	Description string  `json:"description,omitempty"`
	NodeID      string  `json:"nodeId"`
	Focused     bool    `json:"focused,omitempty"`
	Children    []*Node `json:"children,omitempty"`
}

type Tree struct {
	Nodes []*Node `json:"nodes"`
}

func axValueString(v *accessibility.Value) string {
	if v == nil {
		return ""
	}
	raw := string(v.Value)
	return strings.Trim(raw, `"`)
}

func GetTree(ctx context.Context) (*Tree, error) {
	var nodes []*accessibility.Node
	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			nodes, err = accessibility.GetFullAXTree().Do(ctx)
			return err
		}),
	); err != nil {
		return nil, err
	}

	lookup := make(map[string]*Node, len(nodes))
	var roots []*Node

	for _, n := range nodes {
		node := &Node{
			NodeID: string(n.NodeID),
			Role:   axValueString(n.Role),
			Name:   axValueString(n.Name),
		}
		if n.Value != nil {
			node.Value = axValueString(n.Value)
		}
		if n.Description != nil {
			node.Description = axValueString(n.Description)
		}
		for _, prop := range n.Properties {
			if prop.Name == "focused" && prop.Value != nil {
				raw := strings.Trim(string(prop.Value.Value), `"`)
				if raw == "true" {
					node.Focused = true
				}
			}
		}
		lookup[string(n.NodeID)] = node
	}

	for _, n := range nodes {
		self := lookup[string(n.NodeID)]
		for _, cid := range n.ChildIDs {
			if child, ok := lookup[string(cid)]; ok {
				self.Children = append(self.Children, child)
			}
		}
		if n.ParentID == "" {
			roots = append(roots, self)
		}
	}

	return &Tree{Nodes: roots}, nil
}

func GetTreeFiltered(ctx context.Context, roles []string) (*Tree, error) {
	tree, err := GetTree(ctx)
	if err != nil {
		return nil, err
	}

	roleSet := make(map[string]bool, len(roles))
	for _, r := range roles {
		roleSet[r] = true
	}

	var filtered []*Node
	for _, root := range tree.Nodes {
		if f := filterNode(root, roleSet); f != nil {
			filtered = append(filtered, f)
		}
	}
	return &Tree{Nodes: filtered}, nil
}

func filterNode(n *Node, roles map[string]bool) *Node {
	var children []*Node
	for _, c := range n.Children {
		if f := filterNode(c, roles); f != nil {
			children = append(children, f)
		}
	}
	if roles[n.Role] || len(children) > 0 {
		cp := *n
		cp.Children = children
		return &cp
	}
	return nil
}

type FlatElement struct {
	Role  string `json:"role"`
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

func FlattenInteractive(tree *Tree) []FlatElement {
	var result []FlatElement
	for _, root := range tree.Nodes {
		flattenWalk(root, &result)
	}
	return result
}

func flattenWalk(n *Node, result *[]FlatElement) {
	if interactiveRole(n.Role) && n.Name != "" {
		*result = append(*result, FlatElement{
			Role:  n.Role,
			Name:  n.Name,
			Value: n.Value,
		})
	}
	for _, c := range n.Children {
		flattenWalk(c, result)
	}
}

func interactiveRole(role string) bool {
	switch role {
	case "button", "link", "textbox", "checkbox", "radio", "combobox",
		"menuitem", "tab", "switch", "slider", "spinbutton",
		"heading", "img", "navigation", "main", "form",
		"dialog", "alert", "alertdialog", "menu", "menubar",
		"search", "banner", "contentinfo", "complementary",
		"table", "row", "columnheader", "cell",
		"list", "listitem", "treeitem",
		"progressbar", "meter", "status", "log",
		"RootWebArea":
		return true
	}
	return false
}
