// Package api holds the OpenAPI document of the dispatcher, written by hand:
// the admin API and the API of Hydra it emulates for the login apps.
package api

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// YAML is the document as written.
//
//go:embed openapi.yaml
var YAML []byte

// JSON gives the document in JSON, /admin/v1/docs.json: in the order of the
// YAML, which the page of the documentation follows, its anchors and merges
// resolved.
func JSON() ([]byte, error) { return toJSON(YAML) }

func toJSON(data []byte) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var root, more yaml.Node
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	// A second document would be left out without a word (revue R36).
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("openapi.yaml: one document, not more (%v)", err)
	}
	c := converter{path: map[*yaml.Node]bool{}}
	var b bytes.Buffer
	if err := c.writeJSON(&b, &root); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// converter writes a YAML node in JSON; path holds the mappings and
// sequences being written, so that an alias to one of them, which would
// write it inside itself without end, is an error rather than an overflow of
// the stack (revue R36).
type converter struct {
	path map[*yaml.Node]bool
}

func (c converter) enter(n *yaml.Node) error {
	if c.path[n] {
		return fmt.Errorf("openapi.yaml line %d: an alias to a node that holds it", n.Line)
	}
	c.path[n] = true
	return nil
}

func (c converter) writeJSON(b *bytes.Buffer, n *yaml.Node) error {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return errors.New("openapi.yaml: one document")
		}
		return c.writeJSON(b, n.Content[0])
	case yaml.AliasNode:
		return c.writeJSON(b, n.Alias)
	}
	if n.Kind == yaml.SequenceNode || n.Kind == yaml.MappingNode {
		if err := c.enter(n); err != nil {
			return err
		}
		defer delete(c.path, n)
	}
	switch n.Kind {
	case yaml.SequenceNode:
		b.WriteByte('[')
		for i, item := range n.Content {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := c.writeJSON(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	case yaml.MappingNode:
		pairs, err := c.mappingPairs(n)
		if err != nil {
			return err
		}
		b.WriteByte('{')
		for i, p := range pairs {
			if i > 0 {
				b.WriteByte(',')
			}
			key, _ := json.Marshal(p.key)
			b.Write(key)
			b.WriteByte(':')
			if err := c.writeJSON(b, p.value); err != nil {
				return err
			}
		}
		b.WriteByte('}')
		return nil
	case yaml.ScalarNode:
		var v any
		if err := n.Decode(&v); err != nil {
			return err
		}
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("openapi.yaml line %d: %w", n.Line, err)
		}
		b.Write(data)
		return nil
	}
	return fmt.Errorf("openapi.yaml line %d: a node of kind %v", n.Line, n.Kind)
}

type pair struct {
	key   string
	value *yaml.Node
}

// mappingPairs gives the keys of a mapping in their order, those of a merge
// (<<) after them, unless the mapping sets them itself. A merge takes
// mappings alone: a list of anything else was read as pairs (revue R36).
func (c converter) mappingPairs(n *yaml.Node) ([]pair, error) {
	var pairs, merged []pair
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == "<<" && k.Tag == "!!merge" {
			sources := []*yaml.Node{v}
			if v.Kind == yaml.SequenceNode {
				sources = v.Content
			}
			for _, src := range sources {
				for src.Kind == yaml.AliasNode {
					src = src.Alias
				}
				if src.Kind != yaml.MappingNode {
					return nil, fmt.Errorf("openapi.yaml line %d: a merge (<<) of something else than a mapping", src.Line)
				}
				if err := c.enter(src); err != nil {
					return nil, err
				}
				more, err := c.mappingPairs(src)
				delete(c.path, src)
				if err != nil {
					return nil, err
				}
				merged = append(merged, more...)
			}
			continue
		}
		if k.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("openapi.yaml line %d: a key that is not a scalar", k.Line)
		}
		if seen[k.Value] {
			// JSON would hold it twice, each reader keeping one (revue R36).
			return nil, fmt.Errorf("openapi.yaml line %d: %q twice in a mapping", k.Line, k.Value)
		}
		pairs = append(pairs, pair{k.Value, v})
		seen[k.Value] = true
	}
	for _, p := range merged {
		if !seen[p.key] {
			pairs = append(pairs, p)
			seen[p.key] = true
		}
	}
	return pairs, nil
}
