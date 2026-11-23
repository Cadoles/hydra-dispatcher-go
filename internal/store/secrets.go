package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/secretbox"
)

// EncryptedSetting is a value the database holds encrypted, and the kid of the
// key it is under: secrets status. Key names it: a setting's key, or
// apps.<id>.skip_check_key for the key of the pre-check of an app.
type EncryptedSetting struct{ Key, KID string }

// EncryptedSettings reads the encrypted values of the database: the settings
// in the order of the registry, then the keys of the apps by id; an empty
// secret, not encrypted, is none of them.
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
	appKeys, err := readAppKeys(ctx, p.db)
	if err != nil {
		return nil, fmt.Errorf("read the keys of the apps: %w", err)
	}
	for _, k := range appKeys {
		kid, _ := secretbox.KID(k.sealed) // "" for a value of another form: shown, rekey refuses it
		l = append(l, EncryptedSetting{Key: appKeyName(k.id), KID: kid})
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
		appKeys, err := readAppKeys(ctx, tx)
		if err != nil {
			return fmt.Errorf("read the keys of the apps: %w", err)
		}
		for _, k := range appKeys {
			name := appKeyName(k.id)
			if kid, ok := secretbox.KID(k.sealed); ok && kid == p.secrets.Active() {
				continue
			}
			plain, err := p.secrets.Open(name, k.sealed)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			again, err := p.secrets.Seal(name, plain)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE app SET skip_check_key = $2 WHERE id = $1`, k.id, again); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			done = append(done, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return done, nil
}
