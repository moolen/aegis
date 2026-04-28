package policydiscovery

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"google.golang.org/api/iterator"

	"github.com/moolen/aegis/internal/config"
)

type ObjectRef struct {
	Key      string
	URI      string
	Revision string
}

type ObjectStoreClient interface {
	List(ctx context.Context, prefix string) ([]ObjectRef, error)
	Read(ctx context.Context, ref ObjectRef) ([]byte, error)
	Close() error
}

var (
	newAWSObjectStoreClient   = newAWSS3ObjectStoreClient
	newGCPObjectStoreClient   = newGCSObjectStoreClient
	newAzureObjectStoreClient = newAzureBlobObjectStoreClient
)

func NewObjectStoreClient(ctx context.Context, source config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error) {
	normalized := normalizeSourceConfig(source)

	switch normalized.Provider {
	case "aws":
		return newAWSObjectStoreClient(ctx, normalized)
	case "gcp":
		return newGCPObjectStoreClient(ctx, normalized)
	case "azure":
		return newAzureObjectStoreClient(ctx, normalized)
	default:
		return nil, fmt.Errorf("unsupported provider %q", normalized.Provider)
	}
}

type awsObjectStoreClient struct {
	bucket string
	client *s3.Client
}

func newAWSS3ObjectStoreClient(ctx context.Context, source config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS default config: %w", err)
	}
	return &awsObjectStoreClient{
		bucket: source.Bucket,
		client: s3.NewFromConfig(cfg),
	}, nil
}

func (c *awsObjectStoreClient) List(ctx context.Context, prefix string) ([]ObjectRef, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: &c.bucket,
		Prefix: &prefix,
	}
	paginator := s3.NewListObjectsV2Paginator(c.client, input)

	var refs []ObjectRef
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, object := range page.Contents {
			if object.Key == nil {
				continue
			}
			key := *object.Key
			refs = append(refs, ObjectRef{
				Key:      key,
				URI:      fmt.Sprintf("s3://%s/%s", c.bucket, key),
				Revision: awsETag(object),
			})
		}
	}

	return refs, nil
}

func (c *awsObjectStoreClient) Read(ctx context.Context, ref ObjectRef) ([]byte, error) {
	output, err := c.client.GetObject(ctx, newS3GetObjectInput(c.bucket, ref))
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()

	return io.ReadAll(output.Body)
}

func (c *awsObjectStoreClient) Close() error {
	return nil
}

type gcsObjectStoreClient struct {
	bucket string
	client *storage.Client
	closer interface {
		Close() error
	}
}

func newGCSObjectStoreClient(ctx context.Context, source config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create GCS client: %w", err)
	}
	return &gcsObjectStoreClient{
		bucket: source.Bucket,
		client: client,
		closer: client,
	}, nil
}

func (c *gcsObjectStoreClient) List(ctx context.Context, prefix string) ([]ObjectRef, error) {
	iter := c.client.Bucket(c.bucket).Objects(ctx, &storage.Query{Prefix: prefix})

	var refs []ObjectRef
	for {
		attrs, err := iter.Next()
		if err == iterator.Done {
			return refs, nil
		}
		if err != nil {
			return nil, err
		}
		if attrs.Prefix != "" {
			continue
		}
		refs = append(refs, ObjectRef{
			Key:      attrs.Name,
			URI:      fmt.Sprintf("gs://%s/%s", c.bucket, attrs.Name),
			Revision: strconv.FormatInt(attrs.Generation, 10),
		})
	}
}

func (c *gcsObjectStoreClient) Read(ctx context.Context, ref ObjectRef) ([]byte, error) {
	objectHandle := c.client.Bucket(c.bucket).Object(ref.Key)
	if generation, ok, err := gcsGeneration(ref); err != nil {
		return nil, err
	} else if ok {
		objectHandle = objectHandle.Generation(generation)
	}

	reader, err := objectHandle.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

func (c *gcsObjectStoreClient) Close() error {
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

type azureBlobObjectStoreClient struct {
	serviceURL string
	container  string
	client     *azblob.Client
}

func newAzureBlobObjectStoreClient(ctx context.Context, source config.PolicyDiscoverySourceConfig) (ObjectStoreClient, error) {
	accountName := strings.TrimSpace(os.Getenv("AZURE_STORAGE_ACCOUNT_NAME"))
	if accountName == "" {
		accountName = strings.TrimSpace(os.Getenv("AZURE_STORAGE_ACCOUNT"))
	}
	if accountName == "" {
		return nil, fmt.Errorf("AZURE_STORAGE_ACCOUNT_NAME or AZURE_STORAGE_ACCOUNT is required for azure policy discovery")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure default credential: %w", err)
	}

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)
	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure blob client: %w", err)
	}

	return &azureBlobObjectStoreClient{
		serviceURL: serviceURL,
		container:  source.Bucket,
		client:     client,
	}, nil
}

func (c *azureBlobObjectStoreClient) List(ctx context.Context, prefix string) ([]ObjectRef, error) {
	options := &azblob.ListBlobsFlatOptions{Prefix: &prefix}
	pager := c.client.NewListBlobsFlatPager(c.container, options)

	var refs []ObjectRef
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Segment.BlobItems {
			if item == nil || item.Name == nil {
				continue
			}
			key := *item.Name
			refs = append(refs, ObjectRef{
				Key:      key,
				URI:      azureObjectURI(c.serviceURL, c.container, key),
				Revision: azureETag(item),
			})
		}
	}

	return refs, nil
}

func (c *azureBlobObjectStoreClient) Read(ctx context.Context, ref ObjectRef) ([]byte, error) {
	response, err := c.client.DownloadStream(ctx, c.container, ref.Key, newAzureDownloadStreamOptions(ref))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return io.ReadAll(response.Body)
}

func (c *azureBlobObjectStoreClient) Close() error {
	return nil
}

func normalizeSourceConfig(source config.PolicyDiscoverySourceConfig) config.PolicyDiscoverySourceConfig {
	source.Name = strings.TrimSpace(source.Name)
	source.Provider = strings.ToLower(strings.TrimSpace(source.Provider))
	source.Bucket = strings.TrimSpace(source.Bucket)
	source.Prefix = strings.TrimSpace(source.Prefix)
	if strings.TrimSpace(source.Auth.Mode) == "" {
		source.Auth.Mode = "default"
	} else {
		source.Auth.Mode = strings.ToLower(strings.TrimSpace(source.Auth.Mode))
	}
	return source
}

func awsETag(object types.Object) string {
	if object.ETag == nil {
		return ""
	}
	return *object.ETag
}

func newS3GetObjectInput(bucket string, ref ObjectRef) *s3.GetObjectInput {
	input := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &ref.Key,
	}
	if strings.TrimSpace(ref.Revision) != "" {
		input.IfMatch = &ref.Revision
	}
	return input
}

func gcsGeneration(ref ObjectRef) (int64, bool, error) {
	revision := strings.TrimSpace(ref.Revision)
	if revision == "" {
		return 0, false, nil
	}
	generation, err := strconv.ParseInt(revision, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse GCS generation %q for object %q: %w", ref.Revision, ref.Key, err)
	}
	return generation, true, nil
}

func azureETag(item *container.BlobItem) string {
	if item == nil || item.Properties == nil || item.Properties.ETag == nil {
		return ""
	}
	return string(*item.Properties.ETag)
}

func newAzureDownloadStreamOptions(ref ObjectRef) *azblob.DownloadStreamOptions {
	revision := strings.TrimSpace(ref.Revision)
	if revision == "" {
		return nil
	}
	etag := azcore.ETag(revision)
	return &azblob.DownloadStreamOptions{
		AccessConditions: &blob.AccessConditions{
			ModifiedAccessConditions: &blob.ModifiedAccessConditions{
				IfMatch: &etag,
			},
		},
	}
}

func azureObjectURI(serviceURL string, containerName string, blobName string) string {
	return fmt.Sprintf("%s/%s/%s",
		strings.TrimRight(strings.TrimSpace(serviceURL), "/"),
		strings.Trim(strings.TrimSpace(containerName), "/"),
		strings.TrimLeft(blobName, "/"),
	)
}
