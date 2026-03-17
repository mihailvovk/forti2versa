package forti2versa

import (
	"fmt"
	"strings"
)

// namingKeywords are Versa config keywords that CAN take an instance name.
// Whether they actually do in a given context is determined by checking if
// their children have grandchildren (instance containers) vs being leaf keys.
var namingKeywords = map[string]bool{
	"template":                true,
	"org":                     true,
	"org-services":            true,
	"address":                 true,
	"group":                   true,
	"service":                 true,
	"schedule":                true,
	"access-policy-group":     true,
	"access-policy":           true,
	"decryption-policy-group": true,
	"decryption-policy":       true,
	"url-filtering-profile":   true,
	"category-action":         true,
	"recurring":               true,
	"decrypt-profile":         true,
	"service-node-group":      true,
}

// trieNode represents a node in the config hierarchy trie.
type trieNode struct {
	children map[string]*trieNode
	order    []string // insertion order of children keys
}

func newTrieNode() *trieNode {
	return &trieNode{children: make(map[string]*trieNode)}
}

// tokenizeLine splits a set-command line into tokens, keeping bracket lists
// and quoted strings as single tokens.
func tokenizeLine(line string) []string {
	var tokens []string
	i := 0
	for i < len(line) {
		// skip whitespace
		if line[i] == ' ' || line[i] == '\t' {
			i++
			continue
		}
		if line[i] == '[' {
			// find matching ]
			j := strings.Index(line[i:], "]")
			if j >= 0 {
				tokens = append(tokens, line[i:i+j+1])
				i = i + j + 1
			} else {
				tokens = append(tokens, line[i:])
				break
			}
		} else if line[i] == '"' {
			// find matching unescaped "
			j := i + 1
			for j < len(line) {
				if line[j] == '"' && (j == 0 || line[j-1] != '\\') {
					break
				}
				j++
			}
			if j < len(line) {
				tokens = append(tokens, line[i:j+1])
				i = j + 1
			} else {
				tokens = append(tokens, line[i:])
				break
			}
		} else {
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' {
				j++
			}
			tokens = append(tokens, line[i:j])
			i = j
		}
	}
	return tokens
}

// insertPath inserts a token path into the trie.
func (n *trieNode) insertPath(tokens []string) {
	cur := n
	for _, tok := range tokens {
		if _, ok := cur.children[tok]; !ok {
			cur.children[tok] = newTrieNode()
			cur.order = append(cur.order, tok)
		}
		cur = cur.children[tok]
	}
}

// isLeaf returns true if all children of this node are childless (leaf values).
func (n *trieNode) isLeaf() bool {
	if len(n.children) == 0 {
		return true
	}
	for _, child := range n.children {
		if len(child.children) > 0 {
			return false
		}
	}
	return true
}

// isNamingKeywordInContext returns true if this keyword acts as a naming keyword
// in its current trie context. A keyword is naming if it's in the namingKeywords
// set AND at least one of its children (the instance names) is itself a container
// — meaning it has at least one grandchild that also has children. This distinguishes
// "address foo { ipv4-prefix ...; }" (naming) from "address { address-list [...]; }" (container).
func isNamingKeywordInContext(key string, child *trieNode) bool {
	if !namingKeywords[key] {
		return false
	}
	// Check if any child (potential instance name) has children that are NOT all leaves.
	// If a child has at least one grandchild with its own children, then the child
	// is an instance container (has nested properties), confirming this is a naming keyword.
	for _, grandchild := range child.children {
		if !grandchild.isLeaf() {
			return true
		}
	}
	return false
}

// renderStructured renders the trie as a structured config with curly braces.
func renderStructured(node *trieNode, indent int) string {
	var sb strings.Builder
	pad := strings.Repeat("    ", indent)

	for _, key := range node.order {
		child := node.children[key]

		if isNamingKeywordInContext(key, child) {
			// This keyword takes a name argument — iterate its children as named instances
			for _, name := range child.order {
				instance := child.children[name]
				if len(instance.children) == 0 {
					// Named leaf with no properties (rare)
					sb.WriteString(fmt.Sprintf("%s%s %s;\n", pad, key, name))
				} else if instance.isLeaf() {
					// Named instance with only leaf properties
					sb.WriteString(fmt.Sprintf("%s%s %s {\n", pad, key, name))
					sb.WriteString(renderLeafChildren(instance, indent+1))
					sb.WriteString(fmt.Sprintf("%s}\n", pad))
				} else {
					sb.WriteString(fmt.Sprintf("%s%s %s {\n", pad, key, name))
					sb.WriteString(renderStructured(instance, indent+1))
					sb.WriteString(fmt.Sprintf("%s}\n", pad))
				}
			}
		} else if len(child.children) == 0 {
			// Leaf value — key is a standalone flag
			sb.WriteString(fmt.Sprintf("%s%s;\n", pad, key))
		} else if child.isLeaf() {
			// Leaf key-value: all children are values
			vals := strings.Join(child.order, " ")
			sb.WriteString(fmt.Sprintf("%s%s %s;\n", pad, key, vals))
		} else {
			// Container keyword
			sb.WriteString(fmt.Sprintf("%s%s {\n", pad, key))
			sb.WriteString(renderStructured(child, indent+1))
			sb.WriteString(fmt.Sprintf("%s}\n", pad))
		}
	}
	return sb.String()
}

// renderLeafChildren renders only leaf key-value pairs inside a node.
func renderLeafChildren(node *trieNode, indent int) string {
	var sb strings.Builder
	pad := strings.Repeat("    ", indent)
	for _, key := range node.order {
		child := node.children[key]
		if len(child.children) == 0 {
			sb.WriteString(fmt.Sprintf("%s%s;\n", pad, key))
		} else {
			vals := strings.Join(child.order, " ")
			sb.WriteString(fmt.Sprintf("%s%s %s;\n", pad, key, vals))
		}
	}
	return sb.String()
}

// ConvertToStructured converts flat "set ..." lines into structured curly-brace format.
func ConvertToStructured(flatConfig string) string {
	root := newTrieNode()

	for _, line := range strings.Split(flatConfig, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Strip leading "set "
		if strings.HasPrefix(line, "set ") {
			line = line[4:]
		}
		tokens := tokenizeLine(line)
		if len(tokens) == 0 {
			continue
		}
		root.insertPath(tokens)
	}

	return renderStructured(root, 0)
}
