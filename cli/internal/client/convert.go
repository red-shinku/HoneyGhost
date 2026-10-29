package client

import (
	"sort"

	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

func convertRoles(in []*clisv.Role) []model.Role {
	out := make([]model.Role, 0, len(in))
	for _, role := range in {
		out = append(out, model.Role{
			ID:    role.GetRoleID(),
			Label: role.GetRoleLabel(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// convertProcessSet 把 optional 的 pids 缺失转成空切片，root_pid 原样保留。
func convertProcessSet(rootPID uint32, pids *clisv.PidList) model.ProcessSet {
	out := make([]uint32, 0, len(pids.GetPid()))
	out = append(out, pids.GetPid()...)
	return model.ProcessSet{RootPID: rootPID, PIDs: out}
}

// convertUint32s 复制并升序排序，且保证空集合是非 nil 的切片。
func convertUint32s(in []uint32) []uint32 {
	out := make([]uint32, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func convertRoleStats(in *clisv.RM_GetStatsResponse) model.RoleStats {
	return model.RoleStats{
		Rejected:           copyUint64(in.Rejected),
		UnknownInstance:    copyUint64(in.UnknownInstance),
		OwnerConflict:      copyUint64(in.OwnerConflict),
		AnchorsRemoved:     copyUint64(in.AnchorsRemoved),
		CgroupReadEmpty:    copyUint64(in.CgroupReadEmpty),
		QueueRejected:      copyUint64(in.QueueRejected),
		BindDeferred:       copyUint64(in.BindDeferred),
		BindResolved:       copyUint64(in.BindResolved),
		BindRejected:       copyUint64(in.BindRejected),
		BindExpired:        copyUint64(in.BindExpired),
		BindIgnored:        copyUint64(in.BindIgnored),
		LateAdoptRejected:  copyUint64(in.LateAdoptRejected),
		TombstoneDepth:     copyUint64(in.TombstoneDepth),
		DeadMemberRejected: copyUint64(in.DeadMemberRejected),
		DeadAnchorRejected: copyUint64(in.DeadAnchorRejected),
	}
}

func convertContextStats(in *clisv.CM_GetStatsResponse) model.ContextStats {
	return model.ContextStats{
		CtxrootParentUnsettled: uint64Ptr(in.CtxrootParentUnsettled),
		UnknownUnregister:      uint64Ptr(in.UnknownUnregister),
		PendingDeferred:        uint64Ptr(in.PendingDeferred),
		PendingResolved:        uint64Ptr(in.PendingResolved),
		PendingRejected:        uint64Ptr(in.PendingRejected),
		PendingExpired:         uint64Ptr(in.PendingExpired),
		PendingCancelled:       uint64Ptr(in.PendingCancelled),
		PendingDepth:           uint64Ptr(in.PendingDepth),
		BindOrphaned:           uint64Ptr(in.BindOrphaned),
		ExtraOrphaned:          uint64Ptr(in.ExtraOrphaned),
		ParentMissing:          uint64Ptr(in.ParentMissing),
		LateRegister:           uint64Ptr(in.LateRegister),
		LateBind:               uint64Ptr(in.LateBind),
		DuplicateContext:       uint64Ptr(in.DuplicateContext),
		OwnershipConflict:      uint64Ptr(in.OwnershipConflict),
		TombstoneHits:          uint64Ptr(in.TombstoneHits),
		TombstoneDepth:         uint64Ptr(in.TombstoneDepth),
	}
}

func convertProcessStats(in *clisv.PM_GetStatsResponse) model.ProcessStats {
	return model.ProcessStats{
		PidReused:      copyUint64(in.PidReused),
		StaleAdd:       copyUint64(in.StaleAdd),
		ParentMissing:  copyUint64(in.ParentMissing),
		TombstoneDepth: copyUint64(in.TombstoneDepth),
	}
}

func convertWhichRole(in *clisv.RM_WhichRoleResponse) (uint32, bool) {
	if in.RoleID == nil {
		return 0, false
	}
	return in.GetRoleID(), true
}

func convertWhichContext(in *clisv.CM_WhichContextResponse) (uint32, bool) {
	if in.ContextID == nil {
		return 0, false
	}
	return in.GetContextID(), true
}

func copyUint64(in *uint64) *uint64 {
	if in == nil {
		return nil
	}
	return uint64Ptr(*in)
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}
