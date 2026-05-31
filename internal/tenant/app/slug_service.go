package app

import (
	"context"
	"fmt"

	tenantdomain "github.com/krishnaditya65/Project-Janus/internal/tenant/domain"
)

const maxSlugAttempts = 5

type SlugService struct {
	repo tenantdomain.Repository
}

func NewSlugService(repo tenantdomain.Repository) *SlugService {
	return &SlugService{repo: repo}
}

func (s *SlugService) GenerateUniqueSlug(
	ctx context.Context,
	base string,
) (string, error) {

	exists, err := s.repo.ExistsBySlug(ctx, base)
	if err != nil {
		return "", err
	}

	if !exists {
		return base, nil
	}

	for i := 1; i <= maxSlugAttempts; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)

		exists, err := s.repo.ExistsBySlug(ctx, candidate)
		if err != nil {
			return "", err
		}

		if !exists {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("slug %q is unavailable after %d attempts", base, maxSlugAttempts)
}
