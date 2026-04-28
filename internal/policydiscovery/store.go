package policydiscovery

import (
	"bytes"
	"context"
	"fmt"

	"github.com/moolen/aegis/internal/config"
)

type DiscoveredPolicy struct {
	SourceName string
	Object     ObjectRef
	Policy     config.PolicyConfig
}

type Snapshot struct {
	Source   config.PolicyDiscoverySourceConfig
	Objects  []ObjectRef
	Policies []DiscoveredPolicy
}

func CollectSnapshot(ctx context.Context, source config.PolicyDiscoverySourceConfig, client ObjectStoreClient) (Snapshot, error) {
	source = normalizeSourceConfig(source)

	refs, err := client.List(ctx, source.Prefix)
	if err != nil {
		return Snapshot{}, fmt.Errorf("list objects for source %q: %w", source.Name, err)
	}

	snapshot := Snapshot{
		Source:  source,
		Objects: append([]ObjectRef(nil), refs...),
	}

	for _, ref := range refs {
		content, err := client.Read(ctx, ref)
		if err != nil {
			return Snapshot{}, fmt.Errorf("read object %q for source %q: %w", ref.URI, source.Name, err)
		}

		policies, err := Parse(bytes.NewReader(content))
		if err != nil {
			return Snapshot{}, fmt.Errorf("parse object %q for source %q: %w", ref.URI, source.Name, err)
		}

		for _, policy := range policies {
			snapshot.Policies = append(snapshot.Policies, DiscoveredPolicy{
				SourceName: source.Name,
				Object:     ref,
				Policy:     policy,
			})
		}
	}

	return snapshot, nil
}
