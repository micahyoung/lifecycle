package cache

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/buildpacks/imgutil"
	"github.com/buildpacks/imgutil/remote"
	"github.com/pkg/errors"

	"github.com/buildpacks/lifecycle"

	"github.com/google/go-containerregistry/pkg/authn"
)

const MetadataLabel = "io.buildpacks.lifecycle.cache.metadata"

type ImageCache struct {
	committed bool
	origImage imgutil.Image
	newImage  imgutil.Image
}

func NewImageCache(origImage imgutil.Image, newImage imgutil.Image) *ImageCache {
	return &ImageCache{
		origImage: origImage,
		newImage:  newImage,
	}
}

func NewImageCacheFromName(name string, keychain authn.Keychain) (*ImageCache, error) {
	origImage, err := remote.NewImage(
		name,
		keychain,
		remote.FromBaseImage(name),
	)
	if err != nil {
		return nil, fmt.Errorf("accessing cache image %q: %v", name, err)
	}
	emptyImage, err := remote.NewImage(
		name,
		keychain,
		remote.WithPreviousImage(name),
	)
	if err != nil {
		return nil, fmt.Errorf("creating new cache image %q: %v", name, err)
	}
	return NewImageCache(origImage, emptyImage), nil
}

func (c *ImageCache) Name() string {
	return c.origImage.Name()
}

func (c *ImageCache) SetMetadata(metadata lifecycle.CacheMetadata) error {
	if c.committed {
		return errCacheCommitted
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return errors.Wrap(err, "serializing metadata")
	}
	return c.newImage.SetLabel(MetadataLabel, string(data))
}

func (c *ImageCache) RetrieveMetadata() (lifecycle.CacheMetadata, error) {
	var meta lifecycle.CacheMetadata
	if err := lifecycle.DecodeLabel(c.origImage, MetadataLabel, &meta); err != nil {
		return lifecycle.CacheMetadata{}, nil
	}
	return meta, nil
}

func (c *ImageCache) AddLayerFile(tarPath string, diffID string) error {
	if c.committed {
		return errCacheCommitted
	}
	return c.newImage.AddLayerWithDiffID(tarPath, diffID)
}

func (c *ImageCache) ReuseLayer(diffID string) error {
	if c.committed {
		return errCacheCommitted
	}
	return c.newImage.ReuseLayer(diffID)
}

func (c *ImageCache) RetrieveLayer(diffID string) (io.ReadCloser, error) {
	return c.origImage.GetLayer(diffID)
}

func (c *ImageCache) Commit() error {
	if c.committed {
		return errCacheCommitted
	}

	if err := c.newImage.Save(); err != nil {
		return errors.Wrapf(err, "saving image '%s'", c.newImage.Name())
	}
	c.committed = true

	if c.origImage.Found() {
		// Deleting the original image is for cleanup only and should not fail the commit.
		if err := c.DeleteOrigImage(); err != nil {
			fmt.Printf("Unable to delete previous cache image: %v", err)
		}
	}
	c.origImage = c.newImage
	return nil
}

func (c *ImageCache) DeleteOrigImage() error {
	origIdentifier, err := c.origImage.Identifier()
	if err != nil {
		return errors.Wrap(err, "getting identifier for original image")
	}
	newIdentifier, err := c.newImage.Identifier()
	if err != nil {
		return errors.Wrap(err, "getting identifier for new image")
	}
	if origIdentifier.String() == newIdentifier.String() {
		return nil
	}
	return c.origImage.Delete()
}
