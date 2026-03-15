package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type Entity interface {
	GetID() any
	SetCreatedAt(t time.Time)
	SetUpdatedAt(t time.Time)
}

type Repository[T any, ID any] interface {
	Create(ctx context.Context, entity *T) error
	GetByID(ctx context.Context, id ID) (*T, error)
	List(ctx context.Context) ([]T, error)
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id ID) error
}


type BaseRepository[T any, ID any] struct {
	db        *sql.DB
	tableName string
}

func NewBaseRepository[T any, ID any](db *sql.DB, tableName string) *BaseRepository[T, ID] {
	return &BaseRepository[T, ID]{
		db:        db,
		tableName: tableName,
	}
}

func (r *BaseRepository[T, ID]) DB() *sql.DB {
	return r.db
}

func (r *BaseRepository[T, ID]) TableName() string {
	return r.tableName
}

func (r *BaseRepository[T, ID]) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return r.db.ExecContext(ctx, query, args...)
}

func (r *BaseRepository[T, ID]) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return r.db.QueryRowContext(ctx, query, args...)
}

func (r *BaseRepository[T, ID]) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, query, args...)
}

func IsNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

type RowScanner[T any] func(*sql.Row) (*T, error)

type RowsScanner[T any] func(*sql.Rows) (*T, error)

func ScanOne[T any](ctx context.Context, db *sql.DB, scanner RowScanner[T], query string, args ...any) (*T, error) {
	row := db.QueryRowContext(ctx, query, args...)
	return scanner(row)
}

func ScanMany[T any](ctx context.Context, db *sql.DB, scanner RowsScanner[T], query string, args ...any) ([]T, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []T
	for rows.Next() {
		entity, err := scanner(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *entity)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

func WithTransaction[T any](ctx context.Context, db *sql.DB, fn func(*sql.Tx) (T, error)) (T, error) {
	var zero T

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}

	result, err := fn(tx)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return zero, errors.Join(err, rbErr)
		}
		return zero, err
	}

	if err := tx.Commit(); err != nil {
		return zero, err
	}

	return result, nil
}

func WithTransactionNoResult(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Join(err, rbErr)
		}
		return err
	}

	return tx.Commit()
}