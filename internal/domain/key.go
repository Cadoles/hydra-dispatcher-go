package domain

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var errKeySize = errors.New("key must be 32 bytes, given as 64 hex characters or base64")

// ParseKey reads a key of 32 bytes, in 64 hex characters or base64 (standard
// or URL, padded or not), spaces around it dropped: the keys of the
// configuration and the key of the pre-check of an app. "" gives nil.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errKeySize
}

// CheckSkipChecks checks the steps that ask for the pre-check against the
// apps: each names an app with a skip_check_url. A rule of the snapshot as a
// whole, since an app may lose its URL after the flow was written.
func CheckSkipChecks(apps []App, flows []Flow) error {
	url := make(map[string]bool, len(apps))
	for _, a := range apps {
		url[a.ID] = a.SkipCheckURL != ""
	}
	var errs []error
	for _, f := range flows {
		for j, s := range f.Steps {
			if s.SkipCheck && !url[s.AppID] {
				errs = append(errs, fmt.Errorf("flow %s: steps[%d].skip_check: app %s has no skip_check_url", f.ID, j, s.AppID))
			}
		}
	}
	return errors.Join(errs...)
}
