package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/schemalex/schemalex"
	"golang.org/x/xerrors"

	"go.f110.dev/protoc-ddl/internal/generator"
	"go.f110.dev/protoc-ddl/internal/schema"
)

var (
	ErrMigrated = errors.New("already migrated")
)

var SchemaVersionTable *schema.Message

func init() {
	primaryKey := &schema.Field{Name: "sha256", Type: "TYPE_STRING", Size: 64}
	SchemaVersionTable = schema.NewMessage(nil, nil)
	SchemaVersionTable.TableName = "schema_version"
	SchemaVersionTable.Fields = schema.NewFields([]*schema.Field{
		primaryKey,
		{Name: "start_at", Type: schema.TimestampType},
		{Name: "finished_at", Type: schema.TimestampType, Null: true},
	})
	SchemaVersionTable.PrimaryKeys = []*schema.Field{primaryKey}
}

type Migration struct {
	schema             string
	versionTableSchema string
	schemaHash         string
	dsn                string

	db   *sql.DB
	mu   sync.Mutex
	lock *sql.Tx
	diff *Diff
}

func NewMigration(schemaFile, driver, dsn string) (*Migration, error) {
	switch driver {
	case "mysql":
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		cfg.MultiStatements = true
		cfg.ParseTime = true

		dsn = cfg.FormatDSN()
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	buf := new(bytes.Buffer)
	switch driver {
	case "mysql":
		generator.MySQLGenerator{}.Generate(buf, schema.NewMessages([]*schema.Message{SchemaVersionTable}))
	}

	sch, err := ioutil.ReadFile(schemaFile)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	h := sha256.Sum256(sch)

	m := &Migration{schema: string(sch), versionTableSchema: buf.String(), schemaHash: hex.EncodeToString(h[:]), dsn: dsn, db: db}
	if err := m.plan(); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return m, nil
}

func (m *Migration) Execute(ctx context.Context, execute bool) error {
	if !execute {
		return m.dryRun()
	}

	if !m.checkSchemaVersionTable(ctx) {
		if err := m.createSchemaVersionTable(ctx); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if err := m.getLock(ctx); err != nil {
		if err == ErrMigrated {
			return nil
		}
		return xerrors.Errorf(": %w", err)
	}

	for m.diff.Next() {
		log.Printf("Execte: %s", m.diff.Query())
		_, err := m.db.ExecContext(ctx, m.diff.Query())
		if err != nil {
			m.failure()
			return xerrors.Errorf(": %w", err)
		}
	}

	if err := m.finishMigration(ctx, time.Now()); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (m *Migration) dryRun() error {
	for m.diff.Next() {
		fmt.Println(m.diff.Query())
	}

	return nil
}

func (m *Migration) plan() error {
	targetDB := schemalex.NewMySQLSource(m.dsn)

	d, err := NewDiff(targetDB, m.schema)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	m.diff = d

	return nil
}

func (m *Migration) checkSchemaVersionTable(ctx context.Context) bool {
	row := m.db.QueryRowContext(ctx, fmt.Sprintf("SHOW CREATE TABLE %s", SchemaVersionTable.TableName))
	var table, sch string
	if err := row.Scan(&table, &sch); err != nil {
		return false
	}

	return true
}

func (m *Migration) createSchemaVersionTable(ctx context.Context) error {
	log.Printf("Create schema version table: %s", m.versionTableSchema)
	_, err := m.db.ExecContext(ctx, m.versionTableSchema)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (m *Migration) getLock(ctx context.Context) error {
	m.mu.Lock()
	if m.lock != nil {
		m.mu.Unlock()
		return xerrors.New("migrate: Already locked by other instance")
	}
	m.mu.Unlock()

	_, err := m.db.ExecContext(ctx, fmt.Sprintf("INSERT INTO `%s` (`sha256`, `start_at`) VALUES (?, ?)", SchemaVersionTable.TableName), m.schemaHash, time.Now())
	if err != nil {
		mysqlErr, ok := err.(*mysql.MySQLError)
		if !ok {
			return xerrors.Errorf(": %w", err)
		}
		if mysqlErr.Number != 1062 {
			return xerrors.Errorf(": %w", err)
		}
	}

	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	row := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT `finished_at` FROM `%s` WHERE `sha256` = ? FOR UPDATE", SchemaVersionTable.TableName), m.schemaHash)
	var finishedAt *time.Time
	if err := row.Scan(&finishedAt); err != nil {
		tx.Rollback()
		return xerrors.Errorf(": %w", err)
	}
	if finishedAt != nil && !finishedAt.IsZero() {
		tx.Rollback()
		return ErrMigrated
	}

	m.mu.Lock()
	m.lock = tx
	m.mu.Unlock()

	return nil
}

func (m *Migration) failure() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.lock.Rollback()
	m.lock = nil
	return nil
}

func (m *Migration) finishMigration(ctx context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	result, err := m.lock.ExecContext(ctx, fmt.Sprintf("UPDATE `%s` SET `finished_at` = ? WHERE `sha256` = ?", SchemaVersionTable.TableName), now, m.schemaHash)
	if err != nil {
		m.lock.Rollback()
		m.lock = nil
		return xerrors.Errorf(": %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		m.lock.Rollback()
		m.lock = nil
		return xerrors.Errorf(": %w", err)
	}
	if n != 1 {
		m.lock.Rollback()
		m.lock = nil
		return xerrors.Errorf("migrate: Failed update schema version table: %w", err)
	}

	if err := m.lock.Commit(); err != nil {
		m.lock = nil
		return xerrors.Errorf(": %w", err)
	}

	m.lock = nil
	return nil
}
