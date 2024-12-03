package learninggroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/DimTur/lp_auth/internal/domain/models"
	"github.com/DimTur/lp_auth/internal/services/storage"
	"github.com/go-playground/validator/v10"
)

const (
	exchangeShare  = "share"
	spfuRoutingKey = "spfu"
)

type GroupSaver interface {
	SaveLg(ctx context.Context, lg *models.DBCreateLearningGroup) error
	UpdateLgByID(ctx context.Context, lg *models.DBUpdateLearningGroup) error
	UpdateUserInfo(ctx context.Context, userInfo *models.DBUpdateUserInfo) error
}

type GroupeProvider interface {
	GetLgByID(ctx context.Context, userLG *models.GetLgByID) (*models.LearningGroup, error)
	GetLGroupsByUserID(ctx context.Context, userID string) ([]*models.LearningGroupShort, error)
	IsGroupAdmin(ctx context.Context, lgUser *models.IsGroupAdmin) (bool, error)
	IsLearner(ctx context.Context, lgUser *models.GetLgByID) (bool, error)
	GetUserIsGroupAdminIn(ctx context.Context, user *models.UserIsGroupAdminIn) ([]string, error)
	GetUserIsLearnerIn(ctx context.Context, user *models.UserIsLearnerIn) ([]string, error)
	GetLearners(ctx context.Context, lgID *models.GetLearners) ([]string, error)
}

type RabbitMQQueues interface {
	Publish(ctx context.Context, exchange, routingKey string, body []byte) error
	PublishToQueue(ctx context.Context, queueName string, body []byte) error
}

type GroupeDel interface {
	DeleteLgByID(ctx context.Context, delG *models.DelGroup) error
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidGroupID     = errors.New("invalid group id")
	ErrGroupExists        = errors.New("group already exists")
	ErrGroupNotFound      = errors.New("group not found")
	ErrPermissionDenied   = errors.New("you don't have permissions")
	ErrUserNotFound       = errors.New("user not found")
)

type LgHanglers struct {
	log            *slog.Logger
	validator      *validator.Validate
	groupSaver     GroupSaver
	groupeProvider GroupeProvider
	groupeDel      GroupeDel
	rabbitMQQueues RabbitMQQueues
}

func New(
	log *slog.Logger,
	validator *validator.Validate,
	groupSaver GroupSaver,
	groupeProvider GroupeProvider,
	groupeDel GroupeDel,
	rabbitMQQueues RabbitMQQueues,
) *LgHanglers {
	return &LgHanglers{
		log:            log,
		validator:      validator,
		groupSaver:     groupSaver,
		groupeProvider: groupeProvider,
		groupeDel:      groupeDel,
		rabbitMQQueues: rabbitMQQueues,
	}
}

// CreateLearningGroup create new learning group
func (lgh *LgHanglers) CreateLearningGroup(ctx context.Context, lg *models.CreateLearningGroup) error {
	const op = "learning_group.CreateLearningGroup"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("learning_gruop", lg.Name),
		slog.String("creating_by", lg.CreatedBy),
	)

	// Validation
	err := lgh.validator.Struct(lg)
	if err != nil {
		log.Warn("invalid parameters", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	log.Info("creating learning_group")

	dbGroup := &models.DBCreateLearningGroup{
		Name:        lg.Name,
		GroupAdmins: lg.GroupAdmins,
		CreatedBy:   lg.CreatedBy,
		ModifiedBy:  lg.ModifiedBy,
		Created:     time.Now(),
		Updated:     time.Now(),
		Learners:    lg.Learners,
	}

	if err = lgh.groupSaver.SaveLg(ctx, dbGroup); err != nil {
		if errors.Is(err, storage.ErrLgExitsts) {
			lgh.log.Warn("learning_group already exists", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrGroupExists)
		}

		log.Error("failed to save learning_group", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	newRole := &models.DBUpdateUserInfo{
		ID:      lg.CreatedBy,
		Updated: time.Now(),
	}
	if err = lgh.groupSaver.UpdateUserInfo(ctx, newRole); err != nil {
		if errors.Is(err, storage.ErrInvalidCredentials) {
			lgh.log.Warn("invalid credentials", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to update user info", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("learning_group created successfully")

	return nil
}

// GetLgByID returns learning group by ID
func (lgh *LgHanglers) GetLgByID(ctx context.Context, userLG *models.GetLgByID) (*models.LearningGroup, error) {
	const op = "learning_group.GetLgByID"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("user_id", userLG.UserID),
		slog.String("learning_group_id", userLG.LgId),
	)

	log.Info("getting learning_group")

	perm, err := lgh.groupeProvider.IsLearner(ctx, userLG)
	if err != nil {
		log.Error("failed to get learning_group", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if !perm {
		log.Warn("user does not have permission to access learning_group", slog.String("user_id", userLG.UserID))
		return nil, fmt.Errorf("%s: %w", op, ErrPermissionDenied)
	}

	lg, err := lgh.groupeProvider.GetLgByID(ctx, userLG)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrLgNotFound):
			log.Warn("learning_group not found", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, ErrGroupNotFound)
		default:
			log.Error("failed to get learning_group", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	return lg, nil
}

// GetLGroupsByID returns array with info about learning groups related with user
func (lgh *LgHanglers) GetLGroupsByID(ctx context.Context, userID string) ([]*models.LearningGroupShort, error) {
	const op = "learning_group.GetLGroupsByID"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("for user with id", userID),
	)

	log.Info("getting learning_groups")

	lGroups, err := lgh.groupeProvider.GetLGroupsByUserID(ctx, userID)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrLgNotFound):
			return nil, fmt.Errorf("%s: %w", op, ErrGroupNotFound)
		default:
			log.Error("failed to get learning_groups", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	return lGroups, nil
}

// UpdateLearningGroup updates the learning group by all or one field
func (lgh *LgHanglers) UpdateLearningGroup(ctx context.Context, lg *models.UpdateLearningGroup) error {
	const op = "learning_group.UpdateLearningGroup"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("user_id", lg.UserID),
		slog.String("learning_group_id", lg.LgId),
	)

	// Validation
	err := lgh.validator.Struct(lg)
	if err != nil {
		log.Warn("invalid parameters", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	log.Info("updating learning_group")

	isGAdmin := &models.IsGroupAdmin{
		UserID: lg.UserID,
		LgId:   lg.LgId,
	}
	perm, err := lgh.groupeProvider.IsGroupAdmin(ctx, isGAdmin)
	if err != nil {
		log.Error("failed to get learning_group", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}
	if !perm {
		log.Warn("user does not have permission to update learning_group", slog.String("user_id", lg.UserID))
		return fmt.Errorf("%s: %w", op, ErrPermissionDenied)
	}

	updLgGroup := &models.DBUpdateLearningGroup{
		ID:          lg.LgId,
		Name:        lg.Name,
		ModifiedBy:  lg.ModifiedBy,
		Updated:     time.Now(),
		GroupAdmins: lg.GroupAdmins,
		Learners:    lg.Learners,
	}
	if err = lgh.groupSaver.UpdateLgByID(ctx, updLgGroup); err != nil {
		switch {
		case errors.Is(err, storage.ErrLgNotFound):
			log.Warn("learning_group not found", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, ErrGroupNotFound)
		default:
			log.Error("failed to update learning_group", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	if len(lg.Learners) != 0 {
		msg := models.Spfu{
			LearningGroupID: lg.LgId,
			UserIDs:         lg.Learners,
			CreatedBy:       lg.ModifiedBy,
		}

		// Serialization and publication message
		msgBody, err := json.Marshal(msg)
		if err != nil {
			log.Error("failed to marshal msg request", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, err)
		}

		if err = lgh.rabbitMQQueues.Publish(ctx, exchangeShare, spfuRoutingKey, msgBody); err != nil {
			log.Error("failed to publish batch request to spfu queue", slog.String("err", err.Error()))
			return fmt.Errorf("%s: %w", op, err)
		}

		log.Info("learners sent to share with learning group id",
			slog.Any("user_ids", lg.Learners),
			slog.String("learning_group_id", lg.LgId),
		)
	}

	return nil
}

// DeleteLearningGroup deletes learning group by ID
func (lgh *LgHanglers) DeleteLearningGroup(ctx context.Context, lgUser *models.DelGroup) error {
	const op = "learning_group.DeleteLearningGroup"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("user_id", lgUser.UserID),
		slog.String("learning_group_id", lgUser.LgId),
	)

	log.Info("deleting learning_group")

	isGAdmin := &models.IsGroupAdmin{
		UserID: lgUser.UserID,
		LgId:   lgUser.LgId,
	}
	perm, err := lgh.groupeProvider.IsGroupAdmin(ctx, isGAdmin)
	if err != nil {
		log.Error("failed to get learning_group", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}
	if !perm {
		log.Warn("user does not have permission to delete learning_group", slog.String("user_id", lgUser.UserID))
		return fmt.Errorf("%s: %w", op, ErrPermissionDenied)
	}

	if err := lgh.groupeDel.DeleteLgByID(ctx, lgUser); err != nil {
		log.Error("failed to delete learning_group", slog.String("err", err.Error()))
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// IsGroupAdmin checks if the user is a group administrator
func (lgh *LgHanglers) IsGroupAdmin(ctx context.Context, lgUser *models.IsGroupAdmin) (bool, error) {
	const op = "learning_group.IsGroupAdmin"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("user_id", lgUser.UserID),
		slog.String("learning_group_id", lgUser.LgId),
	)

	log.Info("checkin group_admin permissions")

	role, err := lgh.groupeProvider.IsGroupAdmin(ctx, lgUser)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrLgNotFound):
			log.Warn("learning_group not found", slog.String("err", err.Error()))
			return false, fmt.Errorf("%s: %w", op, ErrGroupNotFound)
		default:
			log.Error("user not a group admin", slog.String("err", err.Error()))
			return false, fmt.Errorf("%s: %w", op, err)
		}
	}

	if !role {
		log.Info("checked user is group_admin", slog.Bool("is_groupe_admin", false))
		return false, nil
	}

	log.Info("checked user is group_admin", slog.Bool("is_groupe_admin", true))

	return true, nil
}

// UserIsGroupAdminIn returns id array where user is group admin
func (lgh *LgHanglers) UserIsGroupAdminIn(ctx context.Context, user *models.UserIsGroupAdminIn) ([]string, error) {
	const op = "learning_group.UserIsGroupAdminIn"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("user_id", user.UserID),
	)

	log.Info("checkin group_admin permissions")

	lgIDs, err := lgh.groupeProvider.GetUserIsGroupAdminIn(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrUserNotFound):
			log.Warn("learning_group not found", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		default:
			log.Error("user not a group admin", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	return lgIDs, nil
}

// UserIsLearnerIn returns id array where user is learner
func (lgh *LgHanglers) UserIsLearnerIn(ctx context.Context, user *models.UserIsLearnerIn) ([]string, error) {
	const op = "learning_group.UserIsLearnerIn"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("user_id", user.UserID),
	)

	log.Info("checkin learner permissions")

	lgIDs, err := lgh.groupeProvider.GetUserIsLearnerIn(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrUserNotFound):
			log.Warn("learning_group not found", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		default:
			log.Error("user not a learner", slog.String("err", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	return lgIDs, nil
}

func (lgh *LgHanglers) GetLearners(ctx context.Context, lgID *models.GetLearners) ([]string, error) {
	const op = "learning_group.GetLearners"

	log := lgh.log.With(
		slog.String("op", op),
		slog.String("learning_group_id", lgID.LgId),
	)

	log.Info("getting learners")

	learners, err := lgh.groupeProvider.GetLearners(ctx, lgID)
	if err != nil {
		log.Error("can't get learners", slog.String("err", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return learners, nil
}
