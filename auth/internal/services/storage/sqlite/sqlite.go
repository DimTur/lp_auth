package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/DimTur/learning_platform/auth/internal/domain/models"
	"github.com/DimTur/learning_platform/auth/internal/services/storage"
	"github.com/mattn/go-sqlite3"
)

type SQLLiteStorage struct {
	db *sql.DB
}

// New creates a new instance of the SQLite storage
func New(storagePath string) (SQLLiteStorage, error) {
	const op = "storage.sqlite.New"

	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return SQLLiteStorage{}, fmt.Errorf("%s: %w", op, err)
	}

	return SQLLiteStorage{db: db}, nil
}

func (s *SQLLiteStorage) Close() error {
	return s.db.Close()
}

// SaveUser saves user to db.
func (s *SQLLiteStorage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.sqlite.SaveUser"

	stmt, err := s.db.Prepare("INSERT INTO auth_users(email, pass_hash) VALUES(?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	res, err := stmt.ExecContext(ctx, email, passHash)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExitsts)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	userID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: failed to get last insert id: %w", op, err)
	}

	return userID, nil
}

// User returns user by email.
func (s *SQLLiteStorage) FindUserByEmail(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.FindUserByEmail"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash FROM auth_users WHERE email = ?")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

// IsAdmin checks if user is admin.
func (s *SQLLiteStorage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.sqlite.IsAdmin"

	stmt, err := s.db.Prepare("SELECT is_admin FROM auth_users WHERE id = ?")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, userID)

	var isAdmin bool
	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (s *SQLLiteStorage) FindAppByID(ctx context.Context, appID int64) (models.App, error) {
	const op = "storage.sqlite.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM auth_app WHERE id = ?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, appID)

	var app models.App
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}

func (s *SQLLiteStorage) AddApp(ctx context.Context, name string, secret string) (int64, error) {
	return 0, nil
}
