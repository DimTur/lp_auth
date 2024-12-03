package ssohandlers

import (
	"context"
	"errors"
	"time"

	"github.com/DimTur/lp_auth/internal/domain/models"
	learninggroup "github.com/DimTur/lp_auth/internal/services/learning_group"
	ssov1 "github.com/DimTur/lp_protos/gen/go/sso"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) CreateLearningGroup(ctx context.Context, req *ssov1.CreateLearningGroupRequest) (*ssov1.CreateLearningGroupResponse, error) {
	lg := models.CreateLearningGroup{
		Name:        req.GetName(),
		CreatedBy:   req.GetCreatedBy(),
		ModifiedBy:  req.GetModifiedBy(),
		GroupAdmins: req.GetGroupAdmins(),
		Learners:    req.GetLearners(),
	}
	if err := s.lgh.CreateLearningGroup(ctx, &lg); err != nil {
		switch {
		case errors.Is(err, learninggroup.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "bad request")
		case errors.Is(err, learninggroup.ErrGroupExists):
			return nil, status.Error(codes.AlreadyExists, "learning group exists")
		default:
			return nil, status.Error(codes.Internal, "internal error")
		}
	}

	return &ssov1.CreateLearningGroupResponse{
		Success: true,
	}, nil
}

func (s *serverAPI) GetLearningGroupByID(ctx context.Context, req *ssov1.GetLearningGroupByIDRequest) (*ssov1.GetLearningGroupByIDResponse, error) {
	userLg := models.GetLgByID{
		UserID: req.GetUserId(),
		LgId:   req.GetLearningGroupId(),
	}

	lg, err := s.lgh.GetLgByID(ctx, &userLg)
	if err != nil {
		switch {
		case errors.Is(err, learninggroup.ErrPermissionDenied):
			return nil, status.Error(codes.PermissionDenied, "permissions denied")
		case errors.Is(err, learninggroup.ErrGroupNotFound):
			return nil, status.Error(codes.NotFound, "learning group not found")
		default:
			return nil, status.Error(codes.InvalidArgument, "bad request")
		}
	}

	response := &ssov1.GetLearningGroupByIDResponse{
		Id:          lg.ID,
		Name:        lg.Name,
		CreatedBy:   lg.CreatedBy,
		ModifiedBy:  lg.ModifiedBy,
		Learners:    make([]*ssov1.Learner, len(lg.Learners)),
		GroupAdmins: make([]*ssov1.GroupAdmins, len(lg.GroupAdmins)),
	}

	for i, learner := range lg.Learners {
		response.Learners[i] = &ssov1.Learner{
			Id:    learner.ID,
			Email: learner.Email,
			Name:  learner.Name,
		}
	}

	for i, admin := range lg.GroupAdmins {
		response.GroupAdmins[i] = &ssov1.GroupAdmins{
			Id:    admin.ID,
			Email: admin.Email,
			Name:  admin.Name,
		}
	}

	return response, nil
}

func (s *serverAPI) UpdateLearningGroup(ctx context.Context, req *ssov1.UpdateLearningGroupRequest) (*ssov1.UpdateLearningGroupResponse, error) {
	lg := models.UpdateLearningGroup{
		UserID:      req.GetUserId(),
		LgId:        req.GetLearningGroupId(),
		Name:        req.GetName(),
		ModifiedBy:  req.GetModifiedBy(),
		GroupAdmins: req.GetGroupAdmins(),
		Learners:    req.GetLearners(),
	}
	if err := s.lgh.UpdateLearningGroup(ctx, &lg); err != nil {
		switch {
		case errors.Is(err, learninggroup.ErrPermissionDenied):
			return nil, status.Error(codes.PermissionDenied, "permissions denied")
		case errors.Is(err, learninggroup.ErrGroupNotFound):
			return nil, status.Error(codes.NotFound, "learning group not found")
		case errors.Is(err, learninggroup.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "bad request")
		default:
			return nil, status.Error(codes.Internal, "internal error")
		}
	}

	return &ssov1.UpdateLearningGroupResponse{
		Success: true,
	}, nil
}

func (s *serverAPI) DeleteLearningGroup(ctx context.Context, req *ssov1.DeleteLearningGroupRequest) (*ssov1.DeleteLearningGroupResponse, error) {
	delLg := models.DelGroup{
		UserID: req.GetUserId(),
		LgId:   req.GetLearningGroupId(),
	}

	if err := s.lgh.DeleteLearningGroup(ctx, &delLg); err != nil {
		switch {
		case errors.Is(err, learninggroup.ErrPermissionDenied):
			return nil, status.Error(codes.PermissionDenied, "permissions denied")
		default:
			return nil, status.Error(codes.InvalidArgument, "bad request")
		}
	}

	return &ssov1.DeleteLearningGroupResponse{
		Success: true,
	}, nil
}

func (s *serverAPI) GetLearningGroups(ctx context.Context, req *ssov1.GetLearningGroupsRequest) (*ssov1.GetLearningGroupsResponse, error) {
	lGroups, err := s.lgh.GetLGroupsByID(ctx, req.GetUserId())
	if err != nil {
		switch {
		case errors.Is(err, learninggroup.ErrGroupNotFound):
			return nil, status.Error(codes.NotFound, "learning groups not found")
		default:
			return nil, status.Error(codes.Internal, "internal error")
		}
	}

	response := &ssov1.GetLearningGroupsResponse{
		LearningGroups: make([]*ssov1.LearningGroup, len(lGroups)),
	}

	for i, group := range lGroups {
		response.LearningGroups[i] = &ssov1.LearningGroup{
			Id:         group.ID,
			Name:       group.Name,
			CreatedBy:  group.CreatedBy,
			ModifiedBy: group.ModifiedBy,
			Created:    group.Created.Format(time.RFC3339),
			Updated:    group.Updated.Format(time.RFC3339),
		}
	}

	return response, nil
}

func (s *serverAPI) IsGroupAdmin(ctx context.Context, req *ssov1.IsGroupAdminRequest) (*ssov1.IsGroupAdminResponse, error) {
	isGAdmin := models.IsGroupAdmin{
		UserID: req.GetUserId(),
		LgId:   req.GetLearningGroupId(),
	}

	isGroupAdmin, err := s.lgh.IsGroupAdmin(ctx, &isGAdmin)
	if err != nil {
		if errors.Is(err, learninggroup.ErrGroupNotFound) {
			return nil, status.Error(codes.NotFound, "learning group not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsGroupAdminResponse{
		IsGroupAdmin: isGroupAdmin,
	}, nil
}

func (s *serverAPI) IsUserGroupAdminIn(ctx context.Context, req *ssov1.IsUserGroupAdminInRequest) (*ssov1.IsUserGroupAdminInResponse, error) {
	u := models.UserIsGroupAdminIn{
		UserID: req.GetUserId(),
	}

	lgIDs, err := s.lgh.UserIsGroupAdminIn(ctx, &u)
	if err != nil {
		if errors.Is(err, learninggroup.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsUserGroupAdminInResponse{
		LearningGroupIds: lgIDs,
	}, nil
}

func (s *serverAPI) IsUserLearnerIn(ctx context.Context, req *ssov1.IsUserLearnereInRequest) (*ssov1.IsUserLearnereInResponse, error) {
	u := models.UserIsLearnerIn{
		UserID: req.GetUserId(),
	}

	lgIDs, err := s.lgh.UserIsLearnerIn(ctx, &u)
	if err != nil {
		if errors.Is(err, learninggroup.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsUserLearnereInResponse{
		LearningGroupIds: lgIDs,
	}, nil
}

func (s *serverAPI) GetLearners(ctx context.Context, req *ssov1.GetLearnersRequest) (*ssov1.GetLearnersResponse, error) {
	learners, err := s.lgh.GetLearners(ctx, &models.GetLearners{
		LgId: req.GetLearningGroupId(),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad request")
	}

	return &ssov1.GetLearnersResponse{
		Learners: learners,
	}, nil
}
