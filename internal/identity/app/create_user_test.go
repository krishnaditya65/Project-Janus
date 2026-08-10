package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	authdomain "github.com/krishnaditya65/Project-Janus/internal/auth/domain"
	authorizationdomain "github.com/krishnaditya65/Project-Janus/internal/authorization/domain"
	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
)

// --- fakes ---------------------------------------------------------------

// fakeTxManager runs fn directly against the given ctx - no real
// transactional semantics, just enough to drive CreateUserUseCase.Execute's
// control flow in a unit test.
type fakeTxManager struct{}

func (fakeTxManager) WithinTransaction(
	ctx context.Context,
	fn func(ctx context.Context) error,
) error {
	return fn(ctx)
}

type fakeIdentityRepo struct {
	createErr error
	deleteErr error

	createCalls int
	deleteCalls int
	deletedIDs  []string
}

func (f *fakeIdentityRepo) Create(ctx context.Context, identity *identitydomain.Identity) error {
	f.createCalls++
	return f.createErr
}

func (f *fakeIdentityRepo) GetByEmail(ctx context.Context, email string) (*identitydomain.Identity, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeIdentityRepo) GetByID(ctx context.Context, id string) (*identitydomain.Identity, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeIdentityRepo) Delete(ctx context.Context, id string) error {
	f.deleteCalls++
	f.deletedIDs = append(f.deletedIDs, id)
	return f.deleteErr
}

type fakeCredentialRepo struct {
	createErr error
}

func (f *fakeCredentialRepo) Create(ctx context.Context, credential *authdomain.Credential) error {
	return f.createErr
}

func (f *fakeCredentialRepo) GetByIdentityID(ctx context.Context, identityID string) (*authdomain.Credential, error) {
	return nil, errors.New("not implemented")
}

type fakeUserRepo struct{}

func (fakeUserRepo) Create(ctx context.Context, user *identitydomain.User) error { return nil }
func (fakeUserRepo) GetByID(ctx context.Context, id string) (*identitydomain.User, error) {
	return nil, errors.New("not implemented")
}
func (fakeUserRepo) GetByTenantAndIdentity(ctx context.Context, tenantID, identityID string) (*identitydomain.User, error) {
	return nil, errors.New("not implemented")
}
func (fakeUserRepo) GetByIdentityID(ctx context.Context, identityID string) (*identitydomain.User, error) {
	return nil, errors.New("not implemented")
}
func (fakeUserRepo) GetByTenantAndID(ctx context.Context, tenantID, userID string) (*identitydomain.User, error) {
	return nil, errors.New("not implemented")
}
func (fakeUserRepo) ListByTenant(ctx context.Context, tenantID string) ([]*identitydomain.User, error) {
	return nil, errors.New("not implemented")
}

type fakeUserRoleRepo struct{}

func (fakeUserRoleRepo) AssignRole(ctx context.Context, userRole *authorizationdomain.UserRole) error {
	return nil
}
func (fakeUserRoleRepo) GetRolesForUser(ctx context.Context, userID string) ([]string, error) {
	return nil, errors.New("not implemented")
}

type fakeRoleRepo struct {
	role *authorizationdomain.Role
}

func (f fakeRoleRepo) Create(ctx context.Context, role *authorizationdomain.Role) error { return nil }
func (f fakeRoleRepo) GetByID(ctx context.Context, id string) (*authorizationdomain.Role, error) {
	return nil, errors.New("not implemented")
}
func (f fakeRoleRepo) GetByTenantAndName(ctx context.Context, tenantID, name string) (*authorizationdomain.Role, error) {
	if f.role != nil {
		return f.role, nil
	}
	return nil, errors.New("not implemented")
}
func (f fakeRoleRepo) ListByTenant(ctx context.Context, tenantID string) ([]*authorizationdomain.Role, error) {
	return nil, errors.New("not implemented")
}

// --- helpers ---------------------------------------------------------------

func newTestCreateUserUseCase(
	identityRepo identitydomain.Repository,
	credentialRepo authdomain.Repository,
) *CreateUserUseCase {
	role := &authorizationdomain.Role{ID: "role-1", TenantID: "tenant-1", Name: "member"}

	return NewCreateUserUseCase(
		fakeTxManager{},
		identityRepo,
		credentialRepo,
		fakeUserRepo{},
		fakeRoleRepo{role: role},
		fakeUserRoleRepo{},
	)
}

// --- tests -------------------------------------------------------------

func TestCreateUserUseCase_LocalTransactionFailure_CompensatesByDeletingIdentity(t *testing.T) {
	identityRepo := &fakeIdentityRepo{}
	txFailure := errors.New("credential insert failed")
	credentialRepo := &fakeCredentialRepo{createErr: txFailure}

	uc := newTestCreateUserUseCase(identityRepo, credentialRepo)

	_, err := uc.Execute(context.Background(), CreateUserInput{
		TenantID: "tenant-1",
		Email:    "alice@example.com",
		Password: "supersecret123",
		RoleName: "member",
	})

	if !errors.Is(err, txFailure) {
		t.Fatalf("expected error to wrap/equal the transaction failure, got %v", err)
	}

	if identityRepo.createCalls != 1 {
		t.Fatalf("expected identityRepo.Create to be called once, got %d", identityRepo.createCalls)
	}

	if identityRepo.deleteCalls != 1 {
		t.Fatalf("expected compensating identityRepo.Delete to be called once, got %d", identityRepo.deleteCalls)
	}
}

func TestCreateUserUseCase_CompensatingDeleteFailure_IsSurfacedNotSwallowed(t *testing.T) {
	deleteFailure := errors.New("identity-service unreachable")
	identityRepo := &fakeIdentityRepo{deleteErr: deleteFailure}
	txFailure := errors.New("credential insert failed")
	credentialRepo := &fakeCredentialRepo{createErr: txFailure}

	uc := newTestCreateUserUseCase(identityRepo, credentialRepo)

	_, err := uc.Execute(context.Background(), CreateUserInput{
		TenantID: "tenant-1",
		Email:    "bob@example.com",
		Password: "supersecret123",
		RoleName: "member",
	})

	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	if !errors.Is(err, txFailure) {
		t.Errorf("expected returned error to wrap the original transaction failure, got %v", err)
	}

	if !errors.Is(err, deleteFailure) {
		t.Errorf("expected returned error to wrap the compensating delete failure, got %v", err)
	}

	if !strings.Contains(err.Error(), identityRepo.deletedIDs[0]) {
		t.Errorf("expected error message to reference the orphaned identity ID %q, got %q", identityRepo.deletedIDs[0], err.Error())
	}

	if identityRepo.deleteCalls != 1 {
		t.Fatalf("expected compensating identityRepo.Delete to be called once, got %d", identityRepo.deleteCalls)
	}
}

func TestCreateUserUseCase_Success_DoesNotCompensate(t *testing.T) {
	identityRepo := &fakeIdentityRepo{}
	credentialRepo := &fakeCredentialRepo{}

	uc := newTestCreateUserUseCase(identityRepo, credentialRepo)

	created, err := uc.Execute(context.Background(), CreateUserInput{
		TenantID: "tenant-1",
		Email:    "carol@example.com",
		Password: "supersecret123",
		RoleName: "member",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if created == nil {
		t.Fatal("expected a created user, got nil")
	}

	if identityRepo.createCalls != 1 {
		t.Fatalf("expected identityRepo.Create to be called once, got %d", identityRepo.createCalls)
	}

	if identityRepo.deleteCalls != 0 {
		t.Fatalf("expected no compensating delete on success, got %d calls", identityRepo.deleteCalls)
	}
}
