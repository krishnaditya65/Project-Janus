package http

import authorizationapp "github.com/krishnaditya65/Project-Janus/internal/authorization/app"

type Handler struct {
	createRoleUseCase *authorizationapp.CreateRoleUseCase
	listRolesUseCase  *authorizationapp.ListRolesUseCase

	assignPermissionUseCase    *authorizationapp.AssignPermissionToRoleUseCase
	listRolePermissionsUseCase *authorizationapp.ListRolePermissionsUseCase
}

func NewHandler(
	createRoleUseCase *authorizationapp.CreateRoleUseCase,
	listRolesUseCase *authorizationapp.ListRolesUseCase,

	assignPermissionUseCase *authorizationapp.AssignPermissionToRoleUseCase,
	listRolePermissionsUseCase *authorizationapp.ListRolePermissionsUseCase,
) *Handler {

	return &Handler{
		createRoleUseCase: createRoleUseCase,
		listRolesUseCase:  listRolesUseCase,

		assignPermissionUseCase:    assignPermissionUseCase,
		listRolePermissionsUseCase: listRolePermissionsUseCase,
	}
}
