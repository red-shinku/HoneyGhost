package client

import (
	"reflect"
	"testing"

	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

func TestConvertRolesSortsByID(t *testing.T) {
	got := convertRoles([]*clisv.Role{
		{RoleID: 7, RoleLabel: "nginx"},
		{RoleID: 3, RoleLabel: "ssh"},
	})
	want := []model.Role{
		{ID: 3, Label: "ssh"},
		{ID: 7, Label: "nginx"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("convertRoles = %+v, want %+v", got, want)
	}
}

func TestConvertRolesEmptyIsNonNil(t *testing.T) {
	got := convertRoles(nil)
	if got == nil {
		t.Error("convertRoles(nil) = nil, want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestConvertProcessSet(t *testing.T) {
	got := convertProcessSet(42, &clisv.PidList{Pid: []uint32{9, 8}})
	want := model.ProcessSet{RootPID: 42, PIDs: []uint32{9, 8}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("convertProcessSet = %+v, want %+v", got, want)
	}
}

func TestConvertProcessSetMissingPids(t *testing.T) {
	got := convertProcessSet(42, nil)
	if got.PIDs == nil {
		t.Error("PIDs = nil, want non-nil empty slice")
	}
	if got.RootPID != 42 {
		t.Errorf("RootPID = %d, want 42", got.RootPID)
	}
}

func TestConvertUint32s(t *testing.T) {
	got := convertUint32s([]uint32{5, 1, 3})
	want := []uint32{1, 3, 5}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("convertUint32s = %v, want %v", got, want)
	}
	if got := convertUint32s(nil); got == nil {
		t.Error("convertUint32s(nil) = nil, want non-nil empty slice")
	}
}

func TestConvertRoleStatsCopiesOptionalFields(t *testing.T) {
	value := uint64(3)
	deferred := uint64(7)
	in := &clisv.RM_GetStatsResponse{
		Rejected:        &value,
		UnknownInstance: nil,
		OwnerConflict:   &value,
		BindDeferred:    &deferred,
	}
	got := convertRoleStats(in)
	if got.Rejected == nil || *got.Rejected != 3 {
		t.Errorf("Rejected = %v, want 3", got.Rejected)
	}
	if got.UnknownInstance != nil {
		t.Errorf("UnknownInstance = %v, want nil", got.UnknownInstance)
	}
	if got.BindDeferred == nil || *got.BindDeferred != 7 {
		t.Errorf("BindDeferred = %v, want 7", got.BindDeferred)
	}
	if got.BindResolved != nil {
		t.Errorf("BindResolved = %v, want nil", got.BindResolved)
	}
	value = 9
	deferred = 9
	if *got.Rejected != 3 || *got.BindDeferred != 7 {
		t.Errorf("stats alias proto values: got %d/%d, want 3/7",
			*got.Rejected, *got.BindDeferred)
	}
}

func TestConvertContextStats(t *testing.T) {
	in := &clisv.CM_GetStatsResponse{
		CtxrootParentUnsettled: 1,
		UnknownUnregister:      2,
		PendingDepth:           3,
		TombstoneHits:          4,
	}
	got := convertContextStats(in)
	if got.CtxrootParentUnsettled == nil || *got.CtxrootParentUnsettled != 1 {
		t.Errorf("CtxrootParentUnsettled = %v, want 1", got.CtxrootParentUnsettled)
	}
	if got.UnknownUnregister == nil || *got.UnknownUnregister != 2 {
		t.Errorf("UnknownUnregister = %v, want 2", got.UnknownUnregister)
	}
	if got.PendingDepth == nil || *got.PendingDepth != 3 {
		t.Errorf("PendingDepth = %v, want 3", got.PendingDepth)
	}
	if got.TombstoneHits == nil || *got.TombstoneHits != 4 {
		t.Errorf("TombstoneHits = %v, want 4", got.TombstoneHits)
	}
}

func TestConvertProcessStats(t *testing.T) {
	value := uint64(4)
	in := &clisv.PM_GetStatsResponse{
		PidReused:      &value,
		TombstoneDepth: &value,
	}
	got := convertProcessStats(in)
	if got.PidReused == nil || *got.PidReused != 4 {
		t.Errorf("PidReused = %v, want 4", got.PidReused)
	}
	if got.StaleAdd != nil {
		t.Errorf("StaleAdd = %v, want nil", got.StaleAdd)
	}
	value = 9
	if *got.PidReused != 4 {
		t.Errorf("PidReused aliases proto value: got %d, want 4", *got.PidReused)
	}
}

func TestConvertWhich(t *testing.T) {
	id := uint32(7)
	if got, found := convertWhichRole(&clisv.RM_WhichRoleResponse{RoleID: &id}); got != 7 || !found {
		t.Errorf("convertWhichRole = (%d, %v), want (7, true)", got, found)
	}
	if got, found := convertWhichRole(&clisv.RM_WhichRoleResponse{}); got != 0 || found {
		t.Errorf("convertWhichRole(empty) = (%d, %v), want (0, false)", got, found)
	}

	ctxID := uint32(3)
	if got, found := convertWhichContext(&clisv.CM_WhichContextResponse{ContextID: &ctxID}); got != 3 || !found {
		t.Errorf("convertWhichContext = (%d, %v), want (3, true)", got, found)
	}
	if got, found := convertWhichContext(&clisv.CM_WhichContextResponse{}); got != 0 || found {
		t.Errorf("convertWhichContext(empty) = (%d, %v), want (0, false)", got, found)
	}
}
