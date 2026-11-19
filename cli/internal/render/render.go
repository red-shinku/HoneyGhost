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
	if s.RuntimeStats != nil {
		open()
		ew.println("RUNTIME STATS")
		if err := writePipelineStats(w, *s.RuntimeStats); err != nil {
			return err
		}
	}
	return ew.err
}

// writePipelineStats 按采集、语义、引擎、CLI 四段输出累计计数。
func writePipelineStats(w io.Writer, s model.PipelineStats) error {
	if len(s.Collector) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  LINE	CONSUMED	DROP	REJECT	RESERVE	ERRORS	SKIPPED	ATTACH_FAIL	PENDING_LOST	MALFORMED	STATE")
		for _, line := range s.Collector {
			state := "attached"
			if !line.Attached {
				state = "detached"
			}
			if line.Polling {
				state += "+polling"
			}
			fmt.Fprintf(tw, "  %s	%d	%d	%d	%d	%d	%d	%d	%d	%d	%s\n",
				line.Line, line.Consumed, line.ChannelDropped,
				line.ChannelRejected, line.ReserveFailures,
				line.ConsumeErrors, line.SkippedProbes, line.AttachFailed,
				line.PendingLost, line.Malformed, state)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if s.Semantic != nil {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEMANTIC")
		fmt.Fprintf(tw, "    processed_syscall	%d\n", s.Semantic.ProcessedSyscall)
		fmt.Fprintf(tw, "    raw_syscall_dropped	%d\n", s.Semantic.RawSyscallDropped)
		fmt.Fprintf(tw, "    raw_syscall_rejected	%d\n", s.Semantic.RawSyscallRejected)
		fmt.Fprintf(tw, "    out_syscall_dropped	%d\n", s.Semantic.OutSyscallDropped)
		fmt.Fprintf(tw, "    out_syscall_rejected	%d\n", s.Semantic.OutSyscallRejected)
		fmt.Fprintf(tw, "    path_unresolved	%d\n", s.Semantic.PathUnresolved)
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if s.Engine != nil {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  ENGINE")
		fmt.Fprintf(tw, "    unsettled_events	%d\n", s.Engine.UnsettledEvents)
		fmt.Fprintf(tw, "    peak_cli_streams	%d\n", s.Engine.PeakCLIStreams)
		fmt.Fprintf(tw, "    queue_rejected	%d\n", s.Engine.QueueRejected)
		fmt.Fprintf(tw, "    idle_waits	%d\n", s.Engine.IdleWaits)
		fmt.Fprintf(tw, "    syscall_dropped	%d\n", s.Engine.SyscallDropped)
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if s.CLI != nil {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  CLI STREAMS")
		fmt.Fprintf(tw, "    active	%d\n", s.CLI.Active)
		fmt.Fprintf(tw, "    peak	%d\n", s.CLI.Peak)
		fmt.Fprintf(tw, "    dropped	%d\n", s.CLI.Dropped)
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// events 表格的固定列宽：逐行输出时无法预知后续字段宽度，
// 固定宽度保证每一行都与表头对齐；超宽字段原样溢出，不截断。
const (
	eventHeaderFormat = "%-7s %-9s %-10s %-10s %-10s %-10s %-24s %-10s %s\n"
	eventRowFormat    = "%-7s %-9s %-10d %-10d %-10d %-10d %-24s %-10s %s\n"
)

func (r tableRenderer) Event(w io.Writer, ev model.Event) error {
	st := r.stream
	if !st.headerPrinted {
		st.headerPrinted = true
		if !r.opts.NoHeaders {
			if _, err := fmt.Fprintf(w, eventHeaderFormat,
				"TYPE", "SUBTYPE", "UID", "EUID", "PID", "PPID", "ROLE", "CTX",
				"DETAIL"); err != nil {
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
	subtype := string(ev.Head.Subtype)
	if subtype == "" {
		subtype = "-"
	}

	_, err := fmt.Fprintf(w, eventRowFormat,
		eventType, subtype, ev.Head.UID, ev.Head.EUID, ev.Head.PID, ev.Head.PPID,
		role, contextID, eventDetail(ev.Head, ev.Payload))
	return err
}

// StreamStats 在 table 模式不输出：丢弃提示由命令层写 stderr。
func (r tableRenderer) StreamStats(io.Writer, model.StreamStats) error {
	return nil
}

// initMntNSInum 是初始挂载命名空间的 inode，来源为
// kernel/include/event_head.h 的 HNG_INIT_MNT_NS_INUM；初始命名空间不呈现 MNTNS。
const initMntNSInum uint32 = 4026531840

// 路径字段的解析状态位，取值与 kernel/include/syscall_event_type.h 的
// enum path_flag 一致：bit0 路径被截断，bit1 无法解析为绝对路径。
const pathUnresolvedFlag uint64 = 1 << 1

// eventDetail 生成人读摘要；不是稳定契约，脚本应使用 JSON。
//
// 载荷摘要之后统一追加事件头字段，顺序为 RET、COMM、EXE、MNTNS：RET 恒输出；
// 其余仅在已采集且非空（MNTNS 还要求不是初始命名空间）时输出。
func eventDetail(head model.Head, p model.Payload) string {
	detail := payloadDetail(p)
	detail += fmt.Sprintf(" RET=%d", head.Ret)
	if head.Comm != "" {
		detail += " COMM=" + head.Comm
	}
	if head.Exe != "" {
		detail += " EXE=" + head.Exe
	}
	if head.MntNS != 0 && head.MntNS != initMntNSInum {
		detail += fmt.Sprintf(" MNTNS=%d", head.MntNS)
	}
	return detail
}

// payloadDetail 生成载荷部分的人读摘要。
func payloadDetail(p model.Payload) string {
	fields := p.Fields
	name := stringField(fields, "syscall_name")
	switch p.Kind {
	case model.SubtypeProcess:
		return fmt.Sprintf("%s exit=%v", name, fields["exit_code"])
	case model.SubtypeExec:
		image := stringField(fields, "image")
		if image == "" {
			// 旧事件没有 image：退回语义化路径
			return strings.TrimSpace(name + " " + stringField(fields, "semantic_filename"))
		}
		detail := strings.TrimSpace(name + " image=" + image)
		if invoked := stringField(fields, "invoked"); invoked != "" && invoked != image {
			detail += " invoked=" + invoked
		}
		// 动态库注入特征：LD_PRELOAD 的值原样呈现（可能含多个路径）
		if preload := stringField(fields, "ld_preload"); preload != "" {
			detail += " preload=" + preload
		}
		return detail
	case model.SubtypeCredential:
		return credentialDetail(name, fields)
	case model.SubtypeNamespace:
		return namespaceDetail(name, fields)
	case model.SubtypeFile:
		// 主路径沿用既有 path= 字样，第二路径仅在采集到时追加
		detail := name
		if path := stringField(fields, "path1"); path != "" {
			detail += " path=" + unresolvedPathPrefix(uintField(fields, "path1_flags")) + path
		}
		if path := stringField(fields, "path2"); path != "" {
			detail += " path2=" + unresolvedPathPrefix(uintField(fields, "path2_flags")) + path
		}
		return fmt.Sprintf("%s flags=0x%x mode=0%o", detail,
			uintField(fields, "flags"), uintField(fields, "mode"))
	case model.SubtypeMemory:
		detail := fmt.Sprintf("%s addr=0x%x len=%d prot=0x%x flags=0x%x", name,
			uintField(fields, "addr"), uintField(fields, "length"),
			uintField(fields, "prot"), uintField(fields, "flags"))
		if boolField(fields, "anonymous") {
			detail += " anon"
		} else if path := stringField(fields, "path"); path != "" {
			// 文件映射的源：路径 + 区段起点；解析失败时路径为空，只留 fd 在 JSON
			detail += fmt.Sprintf(" path=%s offset=%d", path,
				uintField(fields, "offset"))
		}
		if boolField(fields, "wx") {
			detail += " wx"
		}
		return detail
	case model.SubtypeNetwork:
		detail := fmt.Sprintf("%s family=%v type=%v protocol=%v", name,
			fields["family"], fields["type"], fields["protocol"])
		unixPath := stringField(fields, "unix_path")
		if uint32(uintField(fields, "family")) == afUNIX && unixPath != "" {
			// AF_UNIX 的目标不是 IP：沿用 dst 字样呈现 sun_path
			return detail + " dst=" + unixPath
		}
		if dst := networkDst(fields); dst != "" {
			detail += fmt.Sprintf(" dst=%s src_port=%d", dst,
				uintField(fields, "src_port"))
		}
		// sockfd 为 -1 表示 socket 事件（新 fd 在 ret）；count 为 0 时省略
		if fd, ok := signedField(fields, "sockfd"); ok && fd >= 0 {
			detail += fmt.Sprintf(" sockfd=%d", fd)
		}
		if count := uintField(fields, "count"); count != 0 {
			detail += fmt.Sprintf(" count=%d", count)
		}
		return detail
	case model.SubtypeKernel:
		// ptrace 呈现目标 pid；bpf 呈现按命令解出的类型（解不出时省略）
		detail := fmt.Sprintf("%s command=%v", name, fields["command"])
		if pid := uintField(fields, "target_pid"); pid != 0 {
			detail += fmt.Sprintf(" pid=%d", pid)
		}
		if bpfType := uintField(fields, "bpf_type"); bpfType != 0 {
			detail += fmt.Sprintf(" type=%d", bpfType)
		}
		return detail
	default:
		return string(p.Kind)
	}
}

// 凭据类别，与 kernel/include/syscall_event_type.h 的 enum credential_kind 以及
// proto credential_semantic_data.kind 同值。
const (
	credentialKindUID  uint32 = 1
	credentialKindGID  uint32 = 2
	credentialKindCAPS uint32 = 3
)

// 命名空间掩码位与呈现名，顺序固定为 MNT、UTS、IPC、USER、PID、NET、CGROUP；
// 位值即内核 CLONE_NEW*。
var namespaceMaskNames = []struct {
	bit  uint32
	name string
}{
	{0x00020000, "MNT"},    // CLONE_NEWNS
	{0x04000000, "UTS"},    // CLONE_NEWUTS
	{0x08000000, "IPC"},    // CLONE_NEWIPC
	{0x10000000, "USER"},   // CLONE_NEWUSER
	{0x20000000, "PID"},    // CLONE_NEWPID
	{0x40000000, "NET"},    // CLONE_NEWNET
	{0x02000000, "CGROUP"}, // CLONE_NEWCGROUP
}

// credentialDetail 生成权限变更摘要：CAPS 呈现三个十六进制能力集，UID/GID 按
// requested 个数呈现单值或多值；requested 为空时只呈现系统调用名。
func credentialDetail(name string, fields map[string]any) string {
	kind := uint32(uintField(fields, "kind"))
	requested, _ := fields["requested"].([]uint32)
	switch kind {
	case credentialKindCAPS:
		capset, _ := fields["capset"].(map[string]any)
		return fmt.Sprintf("%s capset eff=0x%x perm=0x%x inh=0x%x", name,
			uintField(capset, "effective"), uintField(capset, "permitted"),
			uintField(capset, "inheritable"))
	case credentialKindUID, credentialKindGID:
		if len(requested) == 0 {
			return name
		}
		prefix := "uid"
		if kind == credentialKindGID {
			prefix = "gid"
		}
		if len(requested) == 1 {
			return fmt.Sprintf("%s %s=%d", name, prefix, requested[0])
		}
		ids := make([]string, 0, len(requested))
		for _, id := range requested {
			ids = append(ids, strconv.FormatUint(uint64(id), 10))
		}
		return fmt.Sprintf("%s %ss=%s", name, prefix, strings.Join(ids, ","))
	default:
		return name
	}
}

// namespaceDetail 生成命名空间摘要：ns_mask 按固定顺序展开为名字，flags 为 0 时
// 省略，setns 的目标 fd 非负时追加。
func namespaceDetail(name string, fields map[string]any) string {
	detail := name
	if names := namespaceNames(uint32(uintField(fields, "ns_mask"))); names != "" {
		detail += " ns=" + names
	}
	if flags := uintField(fields, "flags"); flags != 0 {
		detail += fmt.Sprintf(" flags=0x%x", flags)
	}
	if fd, ok := signedField(fields, "fd"); ok && fd >= 0 {
		detail += fmt.Sprintf(" fd=%d", fd)
	}
	return detail
}

// namespaceNames 把掩码展开为逗号分隔的命名空间名；无已知位时返回空串。
func namespaceNames(mask uint32) string {
	names := make([]string, 0, len(namespaceMaskNames))
	for _, ns := range namespaceMaskNames {
		if mask&ns.bit != 0 {
			names = append(names, ns.name)
		}
	}
	return strings.Join(names, ",")
}

// 地址族取值，与内核 <sys/socket.h> 的 AF_UNIX / AF_INET / AF_INET6 一致。
const (
	afUNIX  = 1
	afINET  = 2
	afINET6 = 10
)

// networkDst 把网络事件的目标地址与端口拼成 host:port；目标地址未采集时返回
// 空串，此时调用方不呈现 dst（socket/bind 等没有目标的事件）。
func networkDst(fields map[string]any) string {
	words, _ := fields["dst_ip"].([]uint32)
	family := uint32(uintField(fields, "family"))
	port := uintField(fields, "dst_port")

	ip := formatIP(family, words)
	if ip == "" || (port == 0 && allZeroWords(words)) {
		return ""
	}
	if family == afINET6 {
		return "[" + ip + "]:" + strconv.FormatUint(port, 10)
	}
	return ip + ":" + strconv.FormatUint(port, 10)
}

// formatIP 按网络字节序把内核记录的目标地址格式化为可读字符串：IPv4 取
// dst_ip[0] 的四个字节，IPv6 把 dst_ip[0..3] 展开为 8 组 16 位十六进制。
// 地址族不支持或字数不足时返回空串。
func formatIP(family uint32, words []uint32) string {
	switch family {
	case afINET:
		if len(words) < 1 {
			return ""
		}
		word := words[0]
		return fmt.Sprintf("%d.%d.%d.%d", byte(word), byte(word>>8),
			byte(word>>16), byte(word>>24))
	case afINET6:
		if len(words) < 4 {
			return ""
		}
		groups := make([]string, 0, 8)
		for _, word := range words[:4] {
			groups = append(groups,
				fmt.Sprintf("%x", uint16(byte(word))<<8|uint16(byte(word>>8))),
				fmt.Sprintf("%x", uint16(byte(word>>16))<<8|uint16(byte(word>>24))))
		}
		return strings.Join(groups, ":")
	default:
		return ""
	}
}

func allZeroWords(words []uint32) bool {
	for _, word := range words {
		if word != 0 {
			return false
		}
	}
	return true
}

// unresolvedPathPrefix 为无法解析的路径字段生成前缀：探针保留用户原始串，
// 加 ? 与解析出的绝对路径区分；其余状态位不影响呈现。
func unresolvedPathPrefix(flags uint64) string {
	if flags&pathUnresolvedFlag != 0 {
		return "?"
	}
	return ""
}

func stringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

// boolField 取布尔字段；缺失或类型不符时为 false。
func boolField(fields map[string]any, key string) bool {
	value, _ := fields[key].(bool)
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

// signedField 取有符号字段并报告字段是否存在；用于可能为负的 sint32 载荷，
// 如 setns 的目标 fd。
func signedField(fields map[string]any, key string) (int64, bool) {
	switch value := fields[key].(type) {
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case uint32:
		return int64(value), true
	case uint64:
		return int64(value), true
	default:
		return 0, false
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
