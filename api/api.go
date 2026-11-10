// Package api holds the OpenAPI document of the dispatcher, written by hand:
// the admin API and the API of Hydra it emulates for the login apps.
package api

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// YAML is the document as written.
//
//go:embed openapi.yaml
var YAML []byte

// JSON gives the document in JSON, /admin/v1/docs.json: in the order of the
// YAML, which the page of the documentation follows, its anchors and merges
// resolved.
func JSON() ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(YAML, &root); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := writeJSON(&b, &root); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeJSON(b *bytes.Buffer, n *yaml.Node) error {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return errors.New("openapi.yaml: one document")
		}
		return writeJSON(b, n.Content[0])
	case yaml.AliasNode:
		return writeJSON(b, n.Alias)
	case yaml.SequenceNode:
		b.WriteByte('[')
		for i, item := range n.Content {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJSON(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	case yaml.MappingNode:
		pairs, err := mappingPairs(n)
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
			if err := writeJSON(b, p.value); err != nil {
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
// (<<) after them, unless the mapping sets them itself.
func mappingPairs(n *yaml.Node) ([]pair, error) {
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
				more, err := mappingPairs(src)
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
