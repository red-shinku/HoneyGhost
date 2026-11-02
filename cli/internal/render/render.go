package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"honeyghost/cli/internal/model"
)

// Renderer 是 table 与 json 两种输出格式的共同接口。
//
// 渲染器只写调用方给的 writer，不决定 stdout/stderr，不打印错误。
type Renderer interface {
	Roles(w io.Writer, roles []model.Role) error
	RoleDetail(w io.Writer, d model.RoleDetail) error
	RoleStats(w io.Writer, s model.RoleStats) error
	WhichRole(w io.Writer, id uint32, found bool) error
	WhichContext(w io.Writer, id uint32, found bool) error
	ContextList(w io.Writer, refs []model.ContextRef) error
	ContextDetail(w io.Writer, contextID uint32, ps model.ProcessSet) error
	ContextStats(w io.Writer, s model.ContextStats) error
	ProcessStats(w io.Writer, s model.ProcessStats) error
	Status(w io.Writer, s model.Status) error
	Event(w io.Writer, ev model.Event) error
	StreamStats(w io.Writer, s model.StreamStats) error
}

// New 返回指定格式的渲染器；Format 由 ParseFormat 校验。
func New(format Format, opts Options) Renderer {
	if format == FormatJSON {
		return jsonRenderer{}
	}
	return &tableRenderer{opts: opts, stream: &streamState{}}
}

type tableRenderer struct {
	opts   Options
	stream *streamState
}

// streamState 保存流式表格的跨行状态。
type streamState struct {
	headerPrinted bool
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

func (r tableRenderer) RoleDetail(w io.Writer, d model.RoleDetail) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\t%d\n", d.RoleID)
	if d.Label != nil {
		fmt.Fprintf(tw, "LABEL\t%s\n", *d.Label)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	ew := &errWriter{w: w}
	if d.Processes != nil {
		ew.println()
		writeProcessSection(ew, "PROCESSES", *d.Processes)
	}
	if d.ContextIDs != nil {
		ew.println()
		ew.println("CONTEXTS")
		for _, id := range *d.ContextIDs {
			ew.printf("  %d\n", id)
		}
	}
	return ew.err
}

func (r tableRenderer) RoleStats(w io.Writer, s model.RoleStats) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if !r.opts.NoHeaders {
		fmt.Fprintln(tw, "COUNTER\tVALUE")
	}
	writeCounters(tw, roleCounters(s))
	return tw.Flush()
}

func (r tableRenderer) ContextStats(w io.Writer, s model.ContextStats) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if !r.opts.NoHeaders {
		fmt.Fprintln(tw, "COUNTER\tVALUE")
	}
	writeCounters(tw, contextCounters(s))
	return tw.Flush()
}

func (r tableRenderer) ProcessStats(w io.Writer, s model.ProcessStats) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if !r.opts.NoHeaders {
		fmt.Fprintln(tw, "COUNTER\tVALUE")
	}
	writeCounters(tw, processCounters(s))
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

func (r tableRenderer) ContextDetail(w io.Writer, contextID uint32, ps model.ProcessSet) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "CONTEXT\t%d\n", contextID)
	if err := tw.Flush(); err != nil {
		return err
	}

	ew := &errWriter{w: w}
	ew.println()
	writeProcessSection(ew, "PROCESSES", ps)
	return ew.err
}

func (r tableRenderer) Status(w io.Writer, s model.Status) error {
	ew := &errWriter{w: w}
	first := true
	open := func() {
		if !first {
			ew.println()
		}
		first = false
	}

	if s.SupervisedRoleCount != nil || s.ExceptionContextCount != nil ||
		s.ExtraContextCount != nil {
		open()
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if s.SupervisedRoleCount != nil {
			fmt.Fprintf(tw, "SUPERVISED ROLES\t%d\n", *s.SupervisedRoleCount)
		}
		if s.ExceptionContextCount != nil {
			fmt.Fprintf(tw, "EXCEPTION CONTEXTS\t%d\n", *s.ExceptionContextCount)
		}
		if s.ExtraContextCount != nil {
			fmt.Fprintf(tw, "EXTRA CONTEXTS\t%d\n", *s.ExtraContextCount)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if s.RoleStats != nil {
		open()
		ew.println("ROLE STATS")
		if err := writeIndentedCounters(w, roleCounters(*s.RoleStats)); err != nil {
			return err
		}
	}
	if s.ContextStats != nil {
		open()
		ew.println("CONTEXT STATS")
		if err := writeIndentedCounters(w, contextCounters(*s.ContextStats)); err != nil {
			return err
		}
	}
	if s.ProcessStats != nil {
		open()
		ew.println("PROCESS STATS")
		if err := writeIndentedCounters(w, processCounters(*s.ProcessStats)); err != nil {
			return err
		}
	}
	return ew.err
}

// events 表格的固定列宽：逐行输出时无法预知后续字段宽度，
// 固定宽度保证每一行都与表头对齐；超宽字段原样溢出，不截断。
const (
	eventHeaderFormat = "%-7s %-10s %-10s %-24s %-10s %s\n"
	eventRowFormat    = "%-7s %-10d %-10d %-24s %-10s %s\n"
)

func (r tableRenderer) Event(w io.Writer, ev model.Event) error {
	st := r.stream
	if !st.headerPrinted {
		st.headerPrinted = true
		if !r.opts.NoHeaders {
			if _, err := fmt.Fprintf(w, eventHeaderFormat,
				"TYPE", "PID", "PPID", "ROLE", "CTX", "DETAIL"); err != nil {
				return err
			}
		}
	}

	role := ev.Head.RoleLabel
	if role == "" {
		if ev.Head.RoleID != 0 {
			role = fmt.Sprintf("#%d", ev.Head.RoleID)
		} else {
			role = "-"
		}
	}
	contextID := "-"
	if ev.Head.ContextID != 0 {
		contextID = strconv.FormatUint(uint64(ev.Head.ContextID), 10)
	}
	eventType := string(ev.Head.Type)
	if eventType == "" {
		eventType = "-"
	}

	_, err := fmt.Fprintf(w, eventRowFormat,
		eventType, ev.Head.PID, ev.Head.PPID, role, contextID, eventDetail(ev.Payload))
	return err
}

// StreamStats 在 table 模式不输出：丢弃提示由命令层写 stderr。
func (r tableRenderer) StreamStats(io.Writer, model.StreamStats) error {
	return nil
}

// eventDetail 生成人读摘要；不是稳定契约，脚本应使用 JSON。
func eventDetail(p model.Payload) string {
	fields := p.Fields
	name := stringField(fields, "syscall_name")
	switch p.Kind {
	case model.PayloadProcess:
		return fmt.Sprintf("%s exit=%v", name, fields["exit_code"])
	case model.PayloadExec:
		return strings.TrimSpace(name + " " + stringField(fields, "semantic_filename"))
	case model.PayloadCredential:
		if uid, ok := fields["setuid_uid"]; ok {
			return fmt.Sprintf("%s uid=%v", name, uid)
		}
		if gid, ok := fields["setgid_gid"]; ok {
			return fmt.Sprintf("%s gid=%v", name, gid)
		}
		if capset, ok := fields["capset"].(map[string]any); ok {
			return fmt.Sprintf("%s eff=%v perm=%v inh=%v", name,
				capset["effective"], capset["permitted"], capset["inheritable"])
		}
		return name
	case model.PayloadNamespace:
		return fmt.Sprintf("%s ns_type=%v flags=0x%x", name,
			fields["ns_type"], uintField(fields, "flags"))
	case model.PayloadFileSyscall:
		return fmt.Sprintf("%s flags=0x%x mode=0%o", name,
			uintField(fields, "flags"), uintField(fields, "mode"))
	case model.PayloadMemory:
		return fmt.Sprintf("%s prot=0x%x flags=0x%x", name,
			uintField(fields, "prot"), uintField(fields, "flags"))
	case model.PayloadNetworkSyscall:
		return fmt.Sprintf("%s family=%v type=%v protocol=%v", name,
			fields["family"], fields["type"], fields["protocol"])
	case model.PayloadKernel:
		return fmt.Sprintf("%s command=%v arg=%v", name,
			fields["command"], fields["arg"])
	case model.PayloadFile:
		return stringField(fields, "semantic_filename")
	default:
		return p.Kind
	}
}

func stringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func uintField(fields map[string]any, key string) uint64 {
	switch value := fields[key].(type) {
	case uint32:
		return uint64(value)
	case uint64:
		return value
	case int32:
		return uint64(value)
	default:
		return 0
	}
}

func writeProcessSection(ew *errWriter, title string, ps model.ProcessSet) {
	if ps.RootPID == 0 {
		ew.println(title)
	} else {
		ew.printf("%s (root %d)\n", title, ps.RootPID)
	}
	for _, pid := range ps.PIDs {
		ew.printf("  %d\n", pid)
	}
}

type counter struct {
	name  string
	value *uint64
}

func roleCounters(s model.RoleStats) []counter {
	return []counter{
		{"rejected", s.Rejected},
		{"unknown_instance", s.UnknownInstance},
		{"owner_conflict", s.OwnerConflict},
		{"anchors_removed", s.AnchorsRemoved},
		{"cgroup_read_empty", s.CgroupReadEmpty},
		{"queue_rejected", s.QueueRejected},
		{"bind_deferred", s.BindDeferred},
		{"bind_resolved", s.BindResolved},
		{"bind_rejected", s.BindRejected},
		{"bind_expired", s.BindExpired},
		{"bind_ignored", s.BindIgnored},
		{"late_adopt_rejected", s.LateAdoptRejected},
		{"tombstone_depth", s.TombstoneDepth},
		{"dead_member_rejected", s.DeadMemberRejected},
		{"dead_anchor_rejected", s.DeadAnchorRejected},
	}
}

func contextCounters(s model.ContextStats) []counter {
	return []counter{
		{"ctxroot_parent_unsettled", s.CtxrootParentUnsettled},
		{"unknown_unregister", s.UnknownUnregister},
		{"pending_deferred", s.PendingDeferred},
		{"pending_resolved", s.PendingResolved},
		{"pending_rejected", s.PendingRejected},
		{"pending_expired", s.PendingExpired},
		{"pending_cancelled", s.PendingCancelled},
		{"pending_depth", s.PendingDepth},
		{"bind_orphaned", s.BindOrphaned},
		{"extra_orphaned", s.ExtraOrphaned},
		{"parent_missing", s.ParentMissing},
		{"late_register", s.LateRegister},
		{"late_bind", s.LateBind},
		{"duplicate_context", s.DuplicateContext},
		{"ownership_conflict", s.OwnershipConflict},
		{"tombstone_hits", s.TombstoneHits},
		{"tombstone_depth", s.TombstoneDepth},
	}
}

func processCounters(s model.ProcessStats) []counter {
	return []counter{
		{"pid_reused", s.PidReused},
		{"stale_add", s.StaleAdd},
		{"parent_missing", s.ParentMissing},
		{"tombstone_depth", s.TombstoneDepth},
	}
}

func writeCounters(tw *tabwriter.Writer, counters []counter) {
	for _, c := range counters {
		fmt.Fprintf(tw, "%s\t%s\n", c.name, counterValue(c.value))
	}
}

func writeIndentedCounters(w io.Writer, counters []counter) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range counters {
		fmt.Fprintf(tw, "  %s\t%s\n", c.name, counterValue(c.value))
	}
	return tw.Flush()
}

func counterValue(v *uint64) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatUint(*v, 10)
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

func (e *errWriter) println(args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintln(e.w, args...)
}

type jsonRenderer struct{}

func (jsonRenderer) Roles(w io.Writer, roles []model.Role) error {
	return writeJSON(w, nonNilRoles(roles))
}

func (jsonRenderer) RoleDetail(w io.Writer, d model.RoleDetail) error {
	return writeJSON(w, d)
}

func (jsonRenderer) RoleStats(w io.Writer, s model.RoleStats) error {
	return writeJSON(w, s)
}

func (jsonRenderer) ContextStats(w io.Writer, s model.ContextStats) error {
	return writeJSON(w, s)
}

func (jsonRenderer) ProcessStats(w io.Writer, s model.ProcessStats) error {
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

func (jsonRenderer) ContextDetail(w io.Writer, contextID uint32, ps model.ProcessSet) error {
	return writeJSON(w, struct {
		ContextID uint32           `json:"context_id"`
		Processes model.ProcessSet `json:"processes"`
	}{contextID, ps})
}

func (jsonRenderer) Status(w io.Writer, s model.Status) error {
	return writeJSON(w, s)
}

func (jsonRenderer) Event(w io.Writer, ev model.Event) error {
	return writeJSONLine(w, struct {
		Kind    string        `json:"kind"`
		Head    model.Head    `json:"head"`
		Payload model.Payload `json:"payload"`
	}{"event", ev.Head, ev.Payload})
}

func (jsonRenderer) StreamStats(w io.Writer, s model.StreamStats) error {
	return writeJSONLine(w, struct {
		Kind          string `json:"kind"`
		DroppedEvents uint64 `json:"dropped_events"`
	}{"stats", s.DroppedEvents})
}

func writeJSONLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
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
