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
		Rejected:        copyUint64(in.Rejected),
		UnknownInstance: copyUint64(in.UnknownInstance),
		OwnerConflict:   copyUint64(in.OwnerConflict),
		AnchorsRemoved:  copyUint64(in.AnchorsRemoved),
		CgroupReadEmpty: copyUint64(in.CgroupReadEmpty),
		QueueRejected:   copyUint64(in.QueueRejected),
	}
}

func convertContextStats(in *clisv.CM_GetStatsResponse) model.ContextStats {
	return model.ContextStats{
		CtxrootParentUnsettled: uint64Ptr(in.CtxrootParentUnsettled),
		UnknownUnregister:      uint64Ptr(in.UnknownUnregister),
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
