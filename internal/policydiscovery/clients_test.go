package policydiscovery

import (
	"context"
	"testing"

	"github.com/moolen/aegis/internal/config"
)

type fakeConstructedObjectStoreClient struct{}

func (fakeConstructedObjectStoreClient) List(context.Context, string) ([]ObjectRef, error) {
	return nil, nil
}

func (fakeConstructedObjectStoreClient) Read(context.Context, ObjectRef) ([]byte, error) {
	return nil, nil
}

func TestNewObjectStoreClientBuildsAWSClient(t *testing.T) {
	t.Cleanup(func() {
		newAWSObjectStoreClient = newAWSS3ObjectStoreClient
	})

	var gotSource config.PolicyDiscoverySourceConfig
	newAWSObjectStoreClient = func(ctx context.Context, source config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error) {
		gotSource = source
		return fakeConstructedObjectStoreClient{}, nil
	}

	source := config.PolicyDiscoverySourceConfig{
		Name:     "prod-aws",
		Provider: " AWS ",
		Bucket:   "aegis-policies",
		Prefix:   "tenants/",
	}

	client, err := NewObjectStoreClient(context.Background(), source)
	if err != nil {
		t.Fatalf("NewObjectStoreClient() error = %v", err)
	}

	if _, ok := client.(fakeConstructedObjectStoreClient); !ok {
		t.Fatalf("NewObjectStoreClient() client = %T, want fakeConstructedObjectStoreClient", client)
	}
	if gotSource.Provider != "aws" {
		t.Fatalf("provider = %q, want %q", gotSource.Provider, "aws")
	}
	if gotSource.Auth.Mode != "default" {
		t.Fatalf("auth.mode = %q, want %q", gotSource.Auth.Mode, "default")
	}
}

func TestAzureObjectURIIncludesServiceIdentity(t *testing.T) {
	got := azureObjectURI("https://exampleacct.blob.core.windows.net/", "tenant-policies", "teams/a/policy.yaml")
	want := "https://exampleacct.blob.core.windows.net/tenant-policies/teams/a/policy.yaml"

	if got != want {
		t.Fatalf("azureObjectURI() = %q, want %q", got, want)
	}
}
