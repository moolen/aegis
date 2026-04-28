package policydiscovery

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/moolen/aegis/internal/config"
)

type fakeConstructedObjectStoreClient struct{}

func (fakeConstructedObjectStoreClient) List(context.Context, string) ([]ObjectRef, error) {
	return nil, nil
}

func (fakeConstructedObjectStoreClient) Read(context.Context, ObjectRef) ([]byte, error) {
	return nil, nil
}

func (fakeConstructedObjectStoreClient) Close() error {
	return nil
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

func TestS3GetObjectInputUsesRevisionAsIfMatch(t *testing.T) {
	input := newS3GetObjectInput("aegis-policies", ObjectRef{
		Key:      "tenants/team-a/policy.yaml",
		Revision: "\"etag-123\"",
	})

	if input.IfMatch == nil || *input.IfMatch != "\"etag-123\"" {
		t.Fatalf("IfMatch = %#v, want quoted ETag", input.IfMatch)
	}
}

func TestAWSETagPreservesQuotedWireForm(t *testing.T) {
	got := awsETag(types.Object{
		ETag: stringPtr("\"etag-123\""),
	})

	if got != "\"etag-123\"" {
		t.Fatalf("awsETag() = %q, want quoted ETag", got)
	}
}

func TestAzureDownloadOptionsUseRevisionAsIfMatch(t *testing.T) {
	options := newAzureDownloadStreamOptions(ObjectRef{
		Key:      "teams/a/policy.yaml",
		Revision: "\"etag-456\"",
	})

	if options == nil || options.AccessConditions == nil || options.AccessConditions.ModifiedAccessConditions == nil || options.AccessConditions.ModifiedAccessConditions.IfMatch == nil {
		t.Fatal("expected IfMatch access condition")
	}
	if got := *options.AccessConditions.ModifiedAccessConditions.IfMatch; got != azcore.ETag("\"etag-456\"") {
		t.Fatalf("IfMatch = %q, want %q", got, azcore.ETag("\"etag-456\""))
	}
}

func TestGCSGenerationParsesRevision(t *testing.T) {
	generation, ok, err := gcsGeneration(ObjectRef{
		Key:      "teams/a/policy.yaml",
		Revision: "12345",
	})
	if err != nil {
		t.Fatalf("gcsGeneration() error = %v", err)
	}
	if !ok {
		t.Fatal("expected parsed generation")
	}
	if generation != 12345 {
		t.Fatalf("generation = %d, want %d", generation, 12345)
	}
}

func TestAWSAndAzureCloseAreNoOp(t *testing.T) {
	if err := (&awsObjectStoreClient{}).Close(); err != nil {
		t.Fatalf("aws Close() error = %v", err)
	}
	if err := (&azureBlobObjectStoreClient{}).Close(); err != nil {
		t.Fatalf("azure Close() error = %v", err)
	}
}

func TestGCSClientCloseClosesUnderlyingClient(t *testing.T) {
	closer := &fakeCloser{}
	client := &gcsObjectStoreClient{closer: closer}

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !closer.closed {
		t.Fatal("expected Close() to close underlying client")
	}
}

type fakeCloser struct {
	closed bool
}

func (f *fakeCloser) Close() error {
	f.closed = true
	return nil
}

func stringPtr(value string) *string {
	return &value
}
