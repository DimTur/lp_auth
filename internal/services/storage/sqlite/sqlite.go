package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/DimTur/lp_auth/internal/domain/models"
	"github.com/DimTur/lp_auth/internal/services/storage"
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
	defer stmt.Close()

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

// FindUserByEmail returns user by email.
func (s *SQLLiteStorage) FindUserByEmail(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.FindUserByEmail"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash FROM auth_users WHERE email = ?")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

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
	defer stmt.Close()

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

// FindAppByID returns user by id.
func (s *SQLLiteStorage) FindAppByID(ctx context.Context, appID int64) (models.App, error) {
	const op = "storage.sqlite.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM auth_apps WHERE id = ?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

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

// AddApp saves app to db.
//
// TODO: deprecated
func (s *SQLLiteStorage) AddApp(ctx context.Context, name string, secret string) (int64, error) {
	const op = "storage.sqlite.AddApp"

	stmt, err := s.db.Prepare("INSERT INTO auth_apps(name, secret) VALUES(?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, name, secret)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrAppExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	appID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: failed to get last insert id: %w", op, err)
	}

	return appID, nil
}

// SaveRefreshToken saves refresh_token to db.
func (s *SQLLiteStorage) SaveRefreshToken(ctx context.Context, userID int64, token string, expiresAt time.Time) error {
	const op = "storage.sqlite.SaveRefreshToken"

	stmt, err := s.db.PrepareContext(ctx, `INSERT INTO auth_refresh_tokens(user_id, token, expires_at) VALUES(?,?,?)`)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	if _, err := stmt.ExecContext(ctx, userID, token, expiresAt); err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return fmt.Errorf("%s: %w", op, storage.ErrTokenExists)
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// DeleteRefreshToken deletes refresh_token from db.
func (s *SQLLiteStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	const op = "storage.sqlite.DeleteRefreshToken"

	stmt, err := s.db.PrepareContext(ctx, `DELETE FROM auth_refresh_tokens WHERE token = ?`)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, token)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
	}

	return nil
}

// FindRefreshToken finds refresh_token in db.
func (s *SQLLiteStorage) FindRefreshToken(ctx context.Context, userID int64) (models.RefreshToken, error) {
	const op = "storage.sqlite.FindRefreshToken"

	stmt, err := s.db.PrepareContext(ctx, `SELECT token FROM auth_refresh_tokens WHERE user_id = ?`)
	if err != nil {
		return models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	var tokenFromDB string

	err = stmt.QueryRowContext(ctx, userID).Scan(&tokenFromDB)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sql.ErrNoRows {
			return models.RefreshToken{
				Token:  "",
				UserID: userID,
			}, fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
		}

		return models.RefreshToken{}, fmt.Errorf("%s: %w", op, err)
	}

	return models.RefreshToken{
		Token:  tokenFromDB,
		UserID: userID,
	}, nil
}
