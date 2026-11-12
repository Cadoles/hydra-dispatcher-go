package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/secretbox"
)

// EncryptedSetting is a setting the table holds encrypted, and the kid of the
// key it is under: secrets status.
type EncryptedSetting struct{ Key, KID string }

// EncryptedSettings reads the encrypted settings of the table, in the order
// of the registry; an empty secret, not encrypted, is none of them.
func (p *Postgres) EncryptedSettings(ctx context.Context) ([]EncryptedSetting, error) {
	rows, err := readSettings(ctx, p.db)
	if err != nil {
		return nil, fmt.Errorf("read settings: %w", err)
	}
	kids := encryptedKIDs(rows)
	var l []EncryptedSetting
	for _, st := range registry {
		if kid, ok := kids[st.key]; ok {
			l = append(l, EncryptedSetting{Key: st.key, KID: kid})
		}
	}
	return l, nil
}

// Rekey encrypts again by the active key every setting still under another
// key, in one write: under the lock of the writes, the configuration it
// leaves checked, the instances told. Idempotent: what is under the active key
// stays as it is. It returns the keys of the settings encrypted again; their
// updated_at and updated_by stay, their value being the same.
func (p *Postgres) Rekey(ctx context.Context) ([]string, error) {
	if p.secrets.Active() == "" {
		return nil, fmt.Errorf("secrets rekey: %w", secretbox.ErrNoKey)
	}
	var done []string
	err := p.write(ctx, func(tx *sql.Tx) error {
		rows, err := readSettings(ctx, tx)
		if err != nil {
			return fmt.Errorf("read settings: %w", err)
		}
		kids := encryptedKIDs(rows)
		for _, st := range registry {
			kid, ok := kids[st.key]
			if !ok || kid == p.secrets.Active() {
				continue
			}
			var sealed string
			_ = json.Unmarshal(rows[st.key], &sealed) // a string: encryptedKIDs read it
			plain, err := p.secrets.Open(st.key, sealed)
			if err != nil {
				return fmt.Errorf("setting %s: %w", st.key, err)
			}
			again, err := p.secrets.Seal(st.key, plain)
			if err != nil {
				return fmt.Errorf("setting %s: %w", st.key, err)
			}
			value, _ := json.Marshal(again)
			if _, err := tx.ExecContext(ctx, `UPDATE setting SET value = $2::jsonb WHERE key = $1`, st.key, string(value)); err != nil {
				return fmt.Errorf("setting %s: %w", st.key, err)
			}
			done = append(done, st.key)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return done, nil
}
