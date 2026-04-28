package policydiscovery

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/moolen/aegis/internal/config"
)

func TestCollectSnapshotListsReadsAndParsesObjects(t *testing.T) {
	client := &fakeObjectStoreClient{
		refs: []ObjectRef{
			{
				Key:      "tenants/team-a/policy.yaml",
				URI:      "s3://aegis-policies/tenants/team-a/policy.yaml",
				Revision: "rev-a",
			},
			{
				Key:      "tenants/team-b/policies.yaml",
				URI:      "s3://aegis-policies/tenants/team-b/policies.yaml",
				Revision: "rev-b",
			},
		},
		contents: map[string][]byte{
			"tenants/team-a/policy.yaml": []byte(`
apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: allow-team-a
spec:
  subjects:
    cidrs: ["10.20.0.0/16"]
  egress:
    - fqdn: api.example.com
      ports: [443]
      tls:
        mode: passthrough
`),
			"tenants/team-b/policies.yaml": []byte(`
---
apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: allow-team-b
spec:
  subjects:
    cidrs: ["192.168.10.10/24"]
  egress:
    - fqdn: admin.example.com
      ports: [8443]
      tls:
        mode: mitm
---
apiVersion: aegis.io/v1alpha1
kind: ProxyPolicy
metadata:
  name: allow-team-b-db
spec:
  subjects:
    cidrs: ["192.168.20.0/24"]
  egress:
    - fqdn: db.example.com
      ports: [5432]
      tls:
        mode: passthrough
`),
		},
	}

	source := config.PolicyDiscoverySourceConfig{
		Name:     "prod-aws",
		Provider: "aws",
		Bucket:   "aegis-policies",
		Prefix:   "tenants/",
	}

	snapshot, err := CollectSnapshot(context.Background(), source, client)
	if err != nil {
		t.Fatalf("CollectSnapshot() error = %v", err)
	}

	if client.listPrefix != "tenants/" {
		t.Fatalf("List() prefix = %q, want %q", client.listPrefix, "tenants/")
	}

	wantReads := []string{
		"tenants/team-a/policy.yaml@rev-a",
		"tenants/team-b/policies.yaml@rev-b",
	}
	if !reflect.DeepEqual(client.readKeys, wantReads) {
		t.Fatalf("Read() keys = %#v, want %#v", client.readKeys, wantReads)
	}

	want := Snapshot{
		Source: config.PolicyDiscoverySourceConfig{
			Name:     "prod-aws",
			Provider: "aws",
			Bucket:   "aegis-policies",
			Prefix:   "tenants/",
			Auth: config.PolicyDiscoveryAuthConfig{
				Mode: "default",
			},
		},
		Objects: []ObjectRef{
			{
				Key:      "tenants/team-a/policy.yaml",
				URI:      "s3://aegis-policies/tenants/team-a/policy.yaml",
				Revision: "rev-a",
			},
			{
				Key:      "tenants/team-b/policies.yaml",
				URI:      "s3://aegis-policies/tenants/team-b/policies.yaml",
				Revision: "rev-b",
			},
		},
		Policies: []DiscoveredPolicy{
			{
				SourceName: "prod-aws",
				Object: ObjectRef{
					Key:      "tenants/team-a/policy.yaml",
					URI:      "s3://aegis-policies/tenants/team-a/policy.yaml",
					Revision: "rev-a",
				},
				Policy: config.PolicyConfig{
					Name:        "allow-team-a",
					Enforcement: "enforce",
					Subjects: config.PolicySubjectsConfig{
						CIDRs: []string{"10.20.0.0/16"},
					},
					Egress: []config.EgressRuleConfig{
						{
							FQDN:  "api.example.com",
							Ports: []int{443},
							TLS: config.TLSRuleConfig{
								Mode: "passthrough",
							},
						},
					},
				},
			},
			{
				SourceName: "prod-aws",
				Object: ObjectRef{
					Key:      "tenants/team-b/policies.yaml",
					URI:      "s3://aegis-policies/tenants/team-b/policies.yaml",
					Revision: "rev-b",
				},
				Policy: config.PolicyConfig{
					Name:        "allow-team-b",
					Enforcement: "enforce",
					Subjects: config.PolicySubjectsConfig{
						CIDRs: []string{"192.168.10.0/24"},
					},
					Egress: []config.EgressRuleConfig{
						{
							FQDN:  "admin.example.com",
							Ports: []int{8443},
							TLS: config.TLSRuleConfig{
								Mode: "mitm",
							},
						},
					},
				},
			},
			{
				SourceName: "prod-aws",
				Object: ObjectRef{
					Key:      "tenants/team-b/policies.yaml",
					URI:      "s3://aegis-policies/tenants/team-b/policies.yaml",
					Revision: "rev-b",
				},
				Policy: config.PolicyConfig{
					Name:        "allow-team-b-db",
					Enforcement: "enforce",
					Subjects: config.PolicySubjectsConfig{
						CIDRs: []string{"192.168.20.0/24"},
					},
					Egress: []config.EgressRuleConfig{
						{
							FQDN:  "db.example.com",
							Ports: []int{5432},
							TLS: config.TLSRuleConfig{
								Mode: "passthrough",
							},
						},
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(snapshot, want) {
		t.Fatalf("CollectSnapshot() = %#v, want %#v", snapshot, want)
	}
}

type fakeObjectStoreClient struct {
	refs       []ObjectRef
	contents   map[string][]byte
	listPrefix string
	readKeys   []string
	closed     bool
}

func (f *fakeObjectStoreClient) List(ctx context.Context, prefix string) ([]ObjectRef, error) {
	f.listPrefix = prefix
	return f.refs, nil
}

func (f *fakeObjectStoreClient) Read(ctx context.Context, ref ObjectRef) ([]byte, error) {
	f.readKeys = append(f.readKeys, ref.Key+"@"+ref.Revision)
	content, ok := f.contents[ref.Key]
	if !ok {
		return nil, errors.New("missing content")
	}
	return bytes.Clone(content), nil
}

func (f *fakeObjectStoreClient) Close() error {
	f.closed = true
	return nil
}
