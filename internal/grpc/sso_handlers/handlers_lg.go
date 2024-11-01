package ssohandlers

import (
	"context"
	"errors"
	"time"

	"github.com/DimTur/lp_auth/internal/domain/models"
	learninggroup "github.com/DimTur/lp_auth/internal/services/learning_group"
	ssov1 "github.com/DimTur/lp_auth/pkg/server/grpc"
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
			return nil, status.Error(codes.InvalidArgument, "bad request")
		}
	}

	return &ssov1.CreateLearningGroupResponse{
		Success: true,
	}, nil
}

func (s *serverAPI) GetLearningGroupByID(ctx context.Context, req *ssov1.GetLearningGroupByIDRequest) (*ssov1.GetLearningGroupByIDResponse, error) {
	lg, err := s.lgh.GetLgByID(ctx, req.GetId())
	if err != nil {
		switch {
		case errors.Is(err, learninggroup.ErrGroupNotFound):
			return nil, status.Error(codes.NotFound, "learning group not found")
		default:
			return nil, status.Error(codes.InvalidArgument, "bad request")
		}
	}

	response := &ssov1.GetLearningGroupByIDResponse{
		Id:         lg.ID,
		Name:       lg.Name,
		CreatedBy:  lg.CreatedBy,
		ModifiedBy: lg.ModifiedBy,
		Learners:   make([]*ssov1.Learner, len(lg.Learners)),
	}

	for i, learner := range lg.Learners {
		response.Learners[i] = &ssov1.Learner{
			Id:           learner.ID,
			Email:        learner.Email,
			Name:         learner.Name,
			IsAdmin:      learner.IsAdmin,
			IsGroupAdmin: learner.IsGroupAdmin,
		}
	}

	return response, nil
}

func (s *serverAPI) UpdateLearningGroup(ctx context.Context, req *ssov1.UpdateLearningGroupRequest) (*ssov1.UpdateLearningGroupResponse, error) {
	lg := models.UpdateLearningGroup{
		Name:        req.GetName(),
		ModifiedBy:  req.GetModifiedBy(),
		GroupAdmins: req.GetGroupAdmins(),
		Learners:    req.GetLearners(),
	}
	if err := s.lgh.UpdateLearningGroup(ctx, &lg); err != nil {
		switch {
		case errors.Is(err, learninggroup.ErrGroupNotFound):
			return nil, status.Error(codes.NotFound, "learning group not found")
		case errors.Is(err, learninggroup.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "bad request")
		default:
			return nil, status.Error(codes.InvalidArgument, "bad request")
		}
	}

	return &ssov1.UpdateLearningGroupResponse{
		Success: true,
	}, nil
}

func (s *serverAPI) DeleteLearningGroup(ctx context.Context, req *ssov1.DeleteLearningGroupRequest) (*ssov1.DeleteLearningGroupResponse, error) {
	if err := s.lgh.DeleteLearningGroup(ctx, req.GetId()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad request")
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
			return nil, status.Error(codes.InvalidArgument, "bad request")
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
