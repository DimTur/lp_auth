package models

import (
	"time"
)

type LearningGroup struct {
	ID          string      `json:"id" bson:"_id"`
	Name        string      `json:"name" bson:"name"`
	CreatedBy   string      `json:"created_by" bson:"created_by"`
	ModifiedBy  string      `json:"modified_by" bson:"modified_by"`
	Created     time.Time   `json:"created" bson:"created"`
	Updated     time.Time   `json:"updated" bson:"updated"`
	Learners    []GroupUser `json:"learners" bson:"learners"`
	GroupAdmins []GroupUser `json:"group_admins" bson:"group_admins"`
}

type LearningGroupShort struct {
	ID         string    `json:"id" bson:"_id"`
	Name       string    `json:"name" bson:"name"`
	CreatedBy  string    `json:"created_by" bson:"created_by"`
	ModifiedBy string    `json:"modified_by" bson:"modified_by"`
	Created    time.Time `json:"created" bson:"created"`
	Updated    time.Time `json:"updated" bson:"updated"`
}

type CreateLearningGroup struct {
	Name        string   `json:"name" validate:"required,min=3,max=100"`
	CreatedBy   string   `json:"created_by" validate:"required"`
	ModifiedBy  string   `json:"modified_by" validate:"required"`
	GroupAdmins []string `json:"group_admins" validate:"required"`
	Learners    []string `json:"learners" validate:"required"`
}

type GetLgByID struct {
	UserID string `json:"user_id" validate:"required"`
	LgId   string `json:"learning_group_id" validate:"required"`
}

type IsGroupAdmin struct {
	UserID string `json:"user_id" validate:"required"`
	LgId   string `json:"learning_group_id" validate:"required"`
}

type UserIsGroupAdminIn struct {
	UserID string `json:"user_id" validate:"required"`
}

type UserIsLearnerIn struct {
	UserID string `json:"user_id" validate:"required"`
}

type DelGroup struct {
	UserID string `json:"user_id" validate:"required"`
	LgId   string `json:"learning_group_id" validate:"required"`
}

type UpdateLearningGroup struct {
	UserID      string   `json:"user_id" validate:"required"`
	LgId        string   `json:"learning_group_id" validate:"required"`
	Name        string   `json:"name,omitempty"`
	ModifiedBy  string   `json:"modified_by" validate:"required"`
	GroupAdmins []string `json:"group_admins,omitempty"`
	Learners    []string `json:"learners,omitempty"`
}

type GroupUser struct {
	ID    string `json:"_id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type DBCreateLearningGroup struct {
	ID          string    `bson:"_id" validate:"required"`
	Name        string    `bson:"name" validate:"required,min=3,max=100"`
	GroupAdmins []string  `bson:"group_admins" validate:"required"`
	CreatedBy   string    `bson:"created_by" validate:"required"`
	ModifiedBy  string    `bson:"modified_by" validate:"required"`
	Created     time.Time `bson:"created" validate:"required"`
	Updated     time.Time `bson:"updated" validate:"required"`
	Learners    []string  `bson:"learners,omitempty"`
}

type DBUpdateLearningGroup struct {
	ID          string    `bson:"_id" validate:"required"`
	Name        string    `bson:"name,omitempty" validate:"min=3,max=100"`
	ModifiedBy  string    `bson:"modified_by,omitempty" validate:"required"`
	Updated     time.Time `bson:"updated,omitempty" validate:"required"`
	GroupAdmins []string  `bson:"group_admins" validate:"required"`
	Learners    []string  `bson:"learners,omitempty"`
}

type DBLearningGroup struct {
	ID          string        `bson:"_id"`
	Name        string        `bson:"name"`
	CreatedBy   string        `bson:"created_by"`
	ModifiedBy  string        `bson:"modified_by"`
	Created     time.Time     `bson:"created"`
	Updated     time.Time     `bson:"updated"`
	Learners    []DBGroupUser `bson:"learners"`
	GroupAdmins []DBGroupUser `bson:"group_admins"`
}

type DBGroupUser struct {
	ID    string `bson:"_id"`
	Email string `bson:"email"`
	Name  string `bson:"name"`
}

type GetLearners struct {
	LgId string `json:"learning_group_id" validate:"required"`
}

type DBGetLearners struct {
	LgId string `bson:"learning_group_id"`
}

type Spfu struct {
	LearningGroupID string   `json:"learning_group_id"`
	UserIDs         []string `json:"user_ids"`
	CreatedBy       string   `json:"created_by"`
}
