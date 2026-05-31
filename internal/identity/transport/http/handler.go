package http

import identityapp "github.com/krishnaditya65/Project-Janus/internal/identity/app"

type Handler struct {
	getUserUseCase    *identityapp.GetUserUseCase
	listUsersUseCase  *identityapp.ListUsersUseCase
	createUserUseCase *identityapp.CreateUserUseCase
}

func NewHandler(
	getUserUseCase *identityapp.GetUserUseCase,
	listUsersUseCase *identityapp.ListUsersUseCase,
	createUserUseCase *identityapp.CreateUserUseCase,
) *Handler {

	return &Handler{
		getUserUseCase:    getUserUseCase,
		listUsersUseCase:  listUsersUseCase,
		createUserUseCase: createUserUseCase,
	}
}
