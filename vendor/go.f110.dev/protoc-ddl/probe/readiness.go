package probe

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.f110.dev/protoc-ddl/internal/migrate"
)

type Probe struct {
	conn *sql.DB
}

func NewProbe(conn *sql.DB) *Probe {
	return &Probe{conn: conn}
}

func (p *Probe) Ready(ctx context.Context, expect string) bool {
	primaryKey := migrate.SchemaVersionTable.PrimaryKeys[0]
	row := p.conn.QueryRowContext(
		ctx,
		fmt.Sprintf("SELECT `finished_at` FROM `%s` WHERE `%s` = ?", migrate.SchemaVersionTable.TableName, primaryKey.Name),
		expect,
	)
	var finishedAt *time.Time
	if err := row.Scan(&finishedAt); err != nil {
		return false
	}
	if finishedAt != nil && finishedAt.Before(time.Now()) {
		return true
	}

	return false
}
