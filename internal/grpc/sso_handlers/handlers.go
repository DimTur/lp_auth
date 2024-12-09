package ssohandlers

import (
	"context"

	"github.com/DimTur/lp_auth/internal/domain/models"
	ssov1 "github.com/DimTur/lp_protos/gen/go/sso"
	"google.golang.org/grpc"
)

type AuthHandlers interface {
	LoginUser(
		ctx context.Context,
		email string,
		password string,
	) (*models.LogInTokens, error)
	RegisterUser(ctx context.Context, user models.CreateUser) error
	RefreshToken(ctx context.Context, refreshToken string) (string, error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
	AuthCheck(ctx context.Context, accessToken string) (*models.AuthCheck, error)
	LogInViaTg(ctx context.Context, login *models.LogInViaTg) error
	CheckOTP(ctx context.Context, checkOTP *models.LoginUserOTP) (*models.LogInTokens, error)
	UpdateUserInfo(ctx context.Context, userInfo *models.UpdateUserInfo) error
}

type LGHAndlers interface {
	CreateLearningGroup(ctx context.Context, lg *models.CreateLearningGroup) error
	GetLgByID(ctx context.Context, userLG *models.GetLgByID) (*models.LearningGroup, error)
	GetLGroupsByID(ctx context.Context, userID string) ([]*models.LearningGroupShort, error)
	UpdateLearningGroup(ctx context.Context, lg *models.UpdateLearningGroup) error
	DeleteLearningGroup(ctx context.Context, lgUser *models.DelGroup) error
	IsGroupAdmin(ctx context.Context, lgUser *models.IsGroupAdmin) (bool, error)
	UserIsGroupAdminIn(ctx context.Context, user *models.UserIsGroupAdminIn) ([]string, error)
	UserIsLearnerIn(ctx context.Context, user *models.UserIsLearnerIn) ([]string, error)
	GetLearners(ctx context.Context, lgID *models.GetLearners) ([]string, error)
}

type serverAPI struct {
	auth AuthHandlers
	lgh  LGHAndlers

	ssov1.UnimplementedSsoServer
}

func RegisterSsoServiceServer(gRPC *grpc.Server, auth AuthHandlers, lgh LGHAndlers) {
	ssov1.RegisterSsoServer(gRPC, &serverAPI{auth: auth, lgh: lgh})
}
