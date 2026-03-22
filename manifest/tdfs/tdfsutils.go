package tdfs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	tdfsfilesystem "github.com/2DFS/2dfs-builder/filesystem"
	distribution "github.com/2DFS/2dfs-registry/v3"
	"github.com/2DFS/2dfs-registry/v3/manifest/ocischema"
)

type Partition struct {
	x1 int
	y1 int
	x2 int
	y2 int
}

// AllotmentWithPrefetch wraps an Allotment with prefetch metadata
type AllotmentWithPrefetch struct {
	tdfsfilesystem.Allotment
	ShouldPrefetch bool
}

// isInPartition checks if an allotment falls within any of the given partitions
func isInPartition(allotment tdfsfilesystem.Allotment, partitions []Partition) bool {
	for _, p := range partitions {
		if allotment.Row >= p.x1 && allotment.Row <= p.x2 &&
			allotment.Col >= p.y1 && allotment.Col <= p.y2 {
			return true
		}
	}
	return false
}

const (
	//semantic tag partition init char
	partitionInit = `--`
	//semantic tag partition split char
	partitionSplitChar = `.`
	//semantic partition regex patter
	semanticTagPattern = partitionInit + `\d+\` + partitionSplitChar + `\d+\` + partitionSplitChar + `\d+\` + partitionSplitChar + `\d+`
)

// CheckTagPartitions checks if the tag contains semantic partitions and returns the tag and the partitions
func CheckTagPartitions(tag string) (string, []Partition) {
	partitions := []Partition{}
	onlyTag := tag
	re := regexp.MustCompile(semanticTagPattern)
	matches := re.FindAllString(tag, -1)

	if len(matches) > 0 {
		onlyTag = strings.Split(tag, partitionInit)[0]
		//semantic tag with partition
		log.Default().Printf("Semantic tag with partition detected %s\n", tag)
		for _, match := range matches {
			part, err := parsePartition(strings.Replace(match, partitionInit, "", -1))
			if err != nil {
				log.Default().Printf("[WARNING] Invalid partition %s, skipping...\n", match)
				continue
			}
			partitions = append(partitions, part)
			log.Default().Printf("[PARTITIONING...] Added partition %+v \n", part)
		}
	}
	return onlyTag, partitions
}

func parsePartition(p string) (Partition, error) {
	parts := strings.Split(p, partitionSplitChar)
	result := Partition{}
	if len(parts) != 4 {
		return result, fmt.Errorf("invalid partition %s", p)
	}
	var err error
	result.x1, err = strconv.Atoi(parts[0])
	if err != nil {
		return result, err
	}
	result.y1, err = strconv.Atoi(parts[1])
	if err != nil {
		return result, err
	}
	result.x2, err = strconv.Atoi(parts[2])
	if err != nil {
		return result, err
	}
	result.y2, err = strconv.Atoi(parts[3])
	if err != nil {
		return result, err
	}
	return result, nil
}

func ConvertTdfsManifestToOciManifest(ctx context.Context, tdfsManifest *ocischema.DeserializedManifest, blobService distribution.BlobService, partitions []Partition, stargzSupport bool) (distribution.Manifest, error) {
	const p = "[2DFS-TIMING]"

	tTotal := time.Now()
	log.Default().Printf("%s start convert manifest\n", p)

	newLayers := []distribution.Descriptor{}
	allAllotments := []AllotmentWithPrefetch{}

	t := time.Now()
	layerConfigBlob, err := blobService.Get(ctx, tdfsManifest.Config.Digest)
	if err != nil {
		log.Default().Printf("%s error getting config %s\n", p, tdfsManifest.Config.Digest)
		return nil, err
	}
	log.Default().Printf("%s config blob get: %s\n", p, time.Since(t))

	t = time.Now()
	var config v1.Image = v1.Image{}
	err = json.Unmarshal(layerConfigBlob, &config)
	if err != nil {
		log.Default().Printf("%s error unmarshalling config %s\n", p, tdfsManifest.Config.Digest)
		return nil, err
	}
	log.Default().Printf("%s config unmarshal: %s\n", p, time.Since(t))

	//select partitions
	for _, layer := range tdfsManifest.Layers {
		if layer.MediaType == MediaTypeTdfsLayer {
			t = time.Now()
			layerContent, err := blobService.Get(ctx, layer.Digest)
			if err != nil {
				log.Default().Printf("%s error getting layer %s\n", p, layer.Digest)
				return nil, err
			}
			log.Default().Printf("%s field blob get (%d bytes): %s\n", p, len(layerContent), time.Since(t))

			t = time.Now()
			field, err := tdfsfilesystem.GetField().Unmarshal(string(layerContent))
			if err != nil {
				log.Default().Printf("%s error unmarshalling layer %s\n", p, layer.Digest)
				return nil, err
			}
			log.Default().Printf("%s field unmarshal: %s\n", p, time.Since(t))

			// Only process if we haven't collected allotments yet
			if len(allAllotments) == 0 {
				if field != nil {
					seenDigests := make(map[string]*AllotmentWithPrefetch)

					t = time.Now()
					for allotment := range field.IterateAllotments() {
						if allotment.Digest == "" {
							continue
						}

						inPartition := isInPartition(allotment, partitions)

						if stargzSupport {
							// Non-stargz allotments have no lazy loading mechanism, so filter
							// them at the manifest level — only include if they match the partition.
							// Stargz allotments are always included; the runtime handles lazy loading.
							if allotment.TOCDigest == "" && !inPartition {
								continue
							}
						} else {
							// Standard behavior: only include allotments that match the partition.
							if !inPartition {
								continue
							}
						}

						if existing, ok := seenDigests[allotment.Digest]; ok {
							if stargzSupport && !existing.ShouldPrefetch && inPartition {
								existing.ShouldPrefetch = true
							}
							continue
						}

						seenDigests[allotment.Digest] = &AllotmentWithPrefetch{
							Allotment:      allotment,
							ShouldPrefetch: stargzSupport && inPartition,
						}
					}
					log.Default().Printf("%s iterate allotments (%d unique): %s\n", p, len(seenDigests), time.Since(t))

					keys := make([]string, 0, len(seenDigests))
					for k := range seenDigests {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						allAllotments = append(allAllotments, *seenDigests[k])
					}
				}
			}
		} else {
			newLayers = append(newLayers, layer)
		}
	}

	//create new layers
	if len(allAllotments) > 0 {
		t = time.Now()
		for _, awp := range allAllotments {
			tStat := time.Now()
			blob, err := blobService.Stat(ctx, digest.Digest(fmt.Sprintf("sha256:%s", awp.Digest)))
			if err != nil {
				log.Default().Printf("%s unable to find allotment %s\n", p, awp.Digest)
				return nil, err
			}
			log.Default().Printf("%s allotment stat %s: %s\n", p, awp.Digest[:12], time.Since(tStat))

			var layerAnnotations map[string]string
			if stargzSupport {
				annotations := map[string]string{}
				if awp.TOCDigest != "" {
					annotations["containerd.io/snapshot/stargz/toc.digest"] = awp.TOCDigest
				}
				if awp.ShouldPrefetch {
					annotations["containerd.io/snapshot/remote/stargz.prefetch"] = fmt.Sprintf("%d", blob.Size)
				}
				if len(annotations) > 0 {
					layerAnnotations = annotations
				}
			}

			newLayers = append(newLayers, distribution.Descriptor{
				MediaType:   "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:      digest.Digest(fmt.Sprintf("sha256:%s", awp.Digest)),
				Size:        blob.Size,
				Annotations: layerAnnotations,
			})
			config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, digest.Digest(fmt.Sprintf("sha256:%s", awp.DiffID)))
		}
		log.Default().Printf("%s all stat calls (%d allotments): %s\n", p, len(allAllotments), time.Since(t))
	}

	t = time.Now()
	newConfig, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	log.Default().Printf("%s config marshal: %s\n", p, time.Since(t))

	t = time.Now()
	manifestBuilder := ocischema.NewManifestBuilder(blobService, newConfig, tdfsManifest.Annotations)
	err = manifestBuilder.SetMediaType(v1.MediaTypeImageManifest)
	if err != nil {
		log.Default().Printf("%s error setting media type %s\n", p, v1.MediaTypeImageManifest)
		return nil, err
	}
	for _, layer := range newLayers {
		err := manifestBuilder.AppendReference(layer)
		if err != nil {
			log.Default().Printf("%s error appending layer %s\n", p, layer.Digest)
			return nil, err
		}
	}
	manifest, err := manifestBuilder.Build(ctx)
	log.Default().Printf("%s manifest build: %s\n", p, time.Since(t))

	log.Default().Printf("%s total convert: %s\n", p, time.Since(tTotal))
	return manifest, err
}

func ConvertPartitionedIndexToOciIndex(tdfsManifest *ocischema.DeserializedImageIndex) ([]byte, error) {
	log.Default().Printf("Converting partitioned index to OCI index\n")
	return tdfsManifest.MarshalJSON()
}
