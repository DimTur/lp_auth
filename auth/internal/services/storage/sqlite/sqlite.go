package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/DimTur/learning_platform/auth/internal/domain/models"
	"github.com/DimTur/learning_platform/auth/internal/services/storage"
	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
)

type Storage struct {
	db *sql.DB
}

// New creates a new instance of the SQLite storage
func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"

	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

// SaveUser saves user to db.
func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (string, error) {
	const op = "storage.sqlite.SaveUser"

	userID := uuid.New().String()

	stmt, err := s.db.Prepare("INSERT INTO auth_users(id, email, pass_hash) VALUES(?, ?, ?)")
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmt.ExecContext(ctx, userID, email, passHash)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return "", fmt.Errorf("%s: %w", op, storage.ErrUserExitsts)
		}

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return userID, nil
}

// User returns user by email.
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.User"

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
func (s *Storage) IsAdmin(ctx context.Context, userID string) (bool, error) {
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

func (s *Storage) App(ctx context.Context, appID string) (models.App, error) {
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
