package main

import (
	"log/slog"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/coord"
)

// buildCoordination constructs the distributed-coordination Service (Task 56)
// from configuration. It always returns a usable Service: when coordination is
// disabled it hands out always-leader guards so every scheduled job runs on this
// single replica unchanged. For the s3 backend it inherits the cache's S3
// connection settings (cache.s3) for any field left unset under coordination.s3,
// so a deployment already on the shared s3 cache needs only `mode: s3`.
func buildCoordination(cfg *config.Config, logger *slog.Logger) (*coord.Service, error) {
	cc := cfg.Coordination
	ccfg := coord.Config{
		Enabled:       cc.Enabled,
		Mode:          cc.Mode,
		NodeID:        cc.NodeID,
		LeaseTTL:      cc.LeaseTTL,
		RenewInterval: cc.RenewInterval,
		RetryInterval: cc.RetryInterval,
		JobTTLs:       cc.JobTTLs,
		Dir:           cc.Dir,
		S3Prefix:      cc.S3.Prefix,
	}
	if strings.EqualFold(strings.TrimSpace(cc.Mode), "s3") {
		ccfg.S3 = resolveCoordinationS3(cc.S3, cfg.Cache.S3)
	}

	svc, err := coord.New(ccfg, logger)
	if err != nil {
		return nil, err
	}

	switch {
	case !cc.Enabled:
		logger.Info("coordination disabled (single replica: every scheduled job runs here)")
	case strings.EqualFold(strings.TrimSpace(cc.Mode), "memory"), strings.TrimSpace(cc.Mode) == "":
		logger.Warn("coordination mode \"memory\" is in-process only and provides no cross-replica election; " +
			"use mode \"s3\" or \"file\" for a true HA deployment")
	default:
		logger.Info("coordination enabled", "mode", cc.Mode, "node", svc.NodeID(), "leaseTtl", cc.LeaseTTL)
	}
	return svc, nil
}

// resolveCoordinationS3 merges the dedicated coordination.s3 settings over the
// cache.s3 settings field by field, so leases can live in the same bucket and use
// the same credentials as the shared cache unless explicitly overridden.
func resolveCoordinationS3(co config.CoordinationS3Config, cache config.S3CacheConfig) coord.S3Config {
	pick := func(a, b string) string {
		if strings.TrimSpace(a) != "" {
			return a
		}
		return b
	}
	out := coord.S3Config{
		Endpoint:        pick(co.Endpoint, cache.Endpoint),
		Region:          pick(co.Region, cache.Region),
		Bucket:          pick(co.Bucket, cache.Bucket),
		AccessKeyID:     pick(co.AccessKeyID, cache.AccessKeyID),
		SecretAccessKey: pick(co.SecretAccessKey, cache.SecretAccessKey),
		SessionToken:    pick(co.SessionToken, cache.SessionToken),
		MaxRetries:      co.MaxRetries,
	}
	// Booleans inherit from the cache when the coordination block leaves them at
	// their zero value (the common "reuse the cache settings" case).
	out.UsePathStyle = co.UsePathStyle || cache.UsePathStyle
	out.InsecureSkipVerify = co.InsecureSkipVerify || cache.InsecureSkipVerify
	if out.MaxRetries == 0 {
		out.MaxRetries = cache.MaxRetries
	}
	return out
}
