package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"

	"honeyghost/cli/internal/model"
)

// Renderer 是 table 与 json 两种输出格式的共同接口。
//
// 渲染器只写调用方给的 writer，不决定 stdout/stderr，不打印错误。
type Renderer interface {
	Roles(w io.Writer, roles []model.Role) error
	RoleStats(w io.Writer, s model.RoleStats) error
	WhichRole(w io.Writer, id uint32, found bool) error
	WhichContext(w io.Writer, id uint32, found bool) error
	ContextList(w io.Writer, refs []model.ContextRef) error
	ContextStats(w io.Writer, s model.ContextStats) error
}

// New 返回指定格式的渲染器；Format 由 ParseFormat 校验。
func New(format Format, opts Options) Renderer {
	if format == FormatJSON {
		return jsonRenderer{}
	}
	return tableRenderer{opts: opts}
}

type tableRenderer struct {
	opts Options
}

func (r tableRenderer) Roles(w io.Writer, roles []model.Role) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if !r.opts.NoHeaders {
		fmt.Fprintln(tw, "ID\tLABEL")
	}
	for _, role := range roles {
		fmt.Fprintf(tw, "%d\t%s\n", role.ID, role.Label)
	}
	return tw.Flush()
}

func (r tableRenderer) RoleStats(w io.Writer, s model.RoleStats) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if !r.opts.NoHeaders {
		fmt.Fprintln(tw, "COUNTER\tVALUE")
	}
	writeCounter(tw, "rejected", s.Rejected)
	writeCounter(tw, "unknown_instance", s.UnknownInstance)
	writeCounter(tw, "owner_conflict", s.OwnerConflict)
	writeCounter(tw, "anchors_removed", s.AnchorsRemoved)
	writeCounter(tw, "cgroup_read_empty", s.CgroupReadEmpty)
	writeCounter(tw, "queue_rejected", s.QueueRejected)
	return tw.Flush()
}

func (r tableRenderer) ContextStats(w io.Writer, s model.ContextStats) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if !r.opts.NoHeaders {
		fmt.Fprintln(tw, "COUNTER\tVALUE")
	}
	writeCounter(tw, "ctxroot_parent_unsettled", s.CtxrootParentUnsettled)
	writeCounter(tw, "unknown_unregister", s.UnknownUnregister)
	return tw.Flush()
}

func (r tableRenderer) WhichRole(w io.Writer, id uint32, found bool) error {
	if !found {
		return nil
	}
	_, err := fmt.Fprintf(w, "%d\n", id)
	return err
}

func (r tableRenderer) WhichContext(w io.Writer, id uint32, found bool) error {
	if !found {
		return nil
	}
	_, err := fmt.Fprintf(w, "%d\n", id)
	return err
}

func (r tableRenderer) ContextList(w io.Writer, refs []model.ContextRef) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if !r.opts.NoHeaders {
		fmt.Fprintln(tw, "KIND\tCONTEXT_ID")
	}
	for _, ref := range refs {
		fmt.Fprintf(tw, "%s\t%d\n", ref.Kind, ref.ID)
	}
	return tw.Flush()
}

func writeCounter(tw *tabwriter.Writer, name string, v *uint64) {
	value := "-"
	if v != nil {
		value = strconv.FormatUint(*v, 10)
	}
	fmt.Fprintf(tw, "%s\t%s\n", name, value)
}

type jsonRenderer struct{}

func (jsonRenderer) Roles(w io.Writer, roles []model.Role) error {
	return writeJSON(w, nonNilRoles(roles))
}

func (jsonRenderer) RoleStats(w io.Writer, s model.RoleStats) error {
	return writeJSON(w, s)
}

func (jsonRenderer) ContextStats(w io.Writer, s model.ContextStats) error {
	return writeJSON(w, s)
}

func (jsonRenderer) WhichRole(w io.Writer, id uint32, found bool) error {
	var value *uint32
	if found {
		value = &id
	}
	return writeJSON(w, struct {
		RoleID *uint32 `json:"role_id"`
	}{value})
}

func (jsonRenderer) WhichContext(w io.Writer, id uint32, found bool) error {
	var value *uint32
	if found {
		value = &id
	}
	return writeJSON(w, struct {
		ContextID *uint32 `json:"context_id"`
	}{value})
}

func (jsonRenderer) ContextList(w io.Writer, refs []model.ContextRef) error {
	return writeJSON(w, nonNilContextRefs(refs))
}

func writeJSON(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func nonNilRoles(roles []model.Role) []model.Role {
	if roles == nil {
		return []model.Role{}
	}
	return roles
}

func nonNilContextRefs(refs []model.ContextRef) []model.ContextRef {
	if refs == nil {
		return []model.ContextRef{}
	}
	return refs
}
