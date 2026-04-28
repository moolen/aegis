package policydiscovery

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/moolen/aegis/internal/config"
)

func Parse(r io.Reader) ([]config.PolicyConfig, error) {
	decoder := yaml.NewDecoder(r)

	var policies []config.PolicyConfig
	for documentIndex := 1; ; documentIndex++ {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if err == io.EOF {
				return policies, nil
			}
			return nil, fmt.Errorf("decode YAML document %d: %w", documentIndex, err)
		}
		if isEmptyDocument(&document) {
			continue
		}

		resource, err := decodeProxyPolicy(document)
		if err != nil {
			return nil, fmt.Errorf("decode ProxyPolicy document %d: %w", documentIndex, err)
		}
		if strings.TrimSpace(resource.APIVersion) != apiVersion {
			return nil, fmt.Errorf("document %d: apiVersion must be %q", documentIndex, apiVersion)
		}
		if strings.TrimSpace(resource.Kind) != kindProxyPolicy {
			return nil, fmt.Errorf("document %d: kind must be %q", documentIndex, kindProxyPolicy)
		}

		policy, err := resource.Normalize()
		if err != nil {
			return nil, fmt.Errorf("normalize ProxyPolicy document %d: %w", documentIndex, err)
		}
		policies = append(policies, policy)
	}
}

func decodeProxyPolicy(document yaml.Node) (ProxyPolicy, error) {
	content := &document
	if document.Kind == yaml.DocumentNode && len(document.Content) > 0 {
		content = document.Content[0]
	}

	data, err := yaml.Marshal(content)
	if err != nil {
		return ProxyPolicy{}, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var resource ProxyPolicy
	if err := decoder.Decode(&resource); err != nil {
		return ProxyPolicy{}, err
	}
	return resource, nil
}

func isEmptyDocument(node *yaml.Node) bool {
	if node == nil || node.Kind == 0 {
		return true
	}
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return true
		}
		return isEmptyDocument(node.Content[0])
	}
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}
