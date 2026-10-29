package api

import (
	"context"
	"errors"
	"sort"

	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/google/uuid"
)

// RotationApprovals is what the console needs of rotation approvals; the
// rotation service implements it. They live in the same approval_requests as
// deployment approvals and are decided on the same pages.
type RotationApprovals interface {
	GetRotationApproval(ctx context.Context, org, id uuid.UUID) (deployment.Approval, error)
	ListRotationApprovals(ctx context.Context, org uuid.UUID, limit int) ([]deployment.Approval, error)
	DecideRotation(ctx context.Context, in deployment.DecideInput) (deployment.DecideResult, error)
}

// mergedApprovals is the console's view of both kinds of approval. dep may be
// nil when only rotations are served.
type mergedApprovals struct {
	dep ApprovalService
	rot RotationApprovals
}

func (m mergedApprovals) GetApproval(ctx context.Context, org, id uuid.UUID) (deployment.Approval, error) {
	a, err := m.rot.GetRotationApproval(ctx, org, id)
	if !errors.Is(err, deployment.ErrNotFound) {
		return a, err
	}
	if m.dep == nil {
		return deployment.Approval{}, deployment.ErrNotFound
	}
	return m.dep.GetApproval(ctx, org, id)
}

func (m mergedApprovals) ListApprovals(ctx context.Context, org uuid.UUID, limit int) ([]deployment.Approval, error) {
	out, err := m.rot.ListRotationApprovals(ctx, org, limit)
	if err != nil {
		return nil, err
	}
	if m.dep != nil {
		more, err := m.dep.ListApprovals(ctx, org, limit)
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
	}
	open := func(a deployment.Approval) bool { return a.Status == "requested" }
	sort.SliceStable(out, func(i, j int) bool {
		if open(out[i]) != open(out[j]) {
			return open(out[i])
		}
		return out[i].RequestedAt.After(out[j].RequestedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m mergedApprovals) Decide(ctx context.Context, in deployment.DecideInput) (deployment.DecideResult, error) {
	res, err := m.rot.DecideRotation(ctx, in)
	if !errors.Is(err, deployment.ErrNotFound) {
		return res, err
	}
	if m.dep == nil {
		return deployment.DecideResult{}, deployment.ErrNotFound
	}
	return m.dep.Decide(ctx, in)
}

// withRotationApprovals gives the console the rotation approvals too, when
// the rotation service holds any; otherwise the console is left as it was.
func withRotationApprovals(dep ApprovalService, rotations any) ApprovalService {
	if ra, ok := rotations.(RotationApprovals); ok {
		return mergedApprovals{dep: dep, rot: ra}
	}
	return dep
}
