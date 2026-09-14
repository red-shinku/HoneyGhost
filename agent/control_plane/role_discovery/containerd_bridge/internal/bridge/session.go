// Package bridge 把 containerd 侧的事件流与快照段翻译出口，交给 C++ 发现器。
//
// 会话的顺序不变量是「先建流，后快照，且快照段是一次对账」：
//   - 订阅先于枚举，否则枚举与订阅之间启动的容器会被永久漏掉；
//   - 枚举逐 namespace 成段，段起点先发 SnapshotBegin、枚举任一步失败即不发
//     SnapshotEnd，整段作废重走——C++ 侧据此把本段判为作废，不结算；
//   - 段内到达的流内事件不被消费（滞留在合并通道里），段全部收场后才放行，
//     否则段内停止的角色会被读成加入，产出永不修正的幽灵角色。
//
// 本包不判断角色是否加入退出：那是 C++ 侧状态表的事。
package bridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	coreevents "github.com/containerd/containerd/v2/core/events"

	"honeyghost/containerd_bridge/internal/protocol"
	"honeyghost/containerd_bridge/internal/source"
	"honeyghost/containerd_bridge/internal/translator"
)

// sourceName 是随协议上报的后端标注，仅供日志与校验，不进 C++ 侧的状态表。
const sourceName = "containerd-bridge"

// ErrOutputClosed 表示与 C++ 的连接已不可用，会话不再重连后端。
var ErrOutputClosed = errors.New("与 C++ 的连接已不可用")

// Config 是会话参数。
type Config struct {
	// Address 是 containerd 的 socket 路径。
	Address string

	// Namespaces 是跟踪的 namespace。不在列表内的 namespace 既不订阅也不枚举，
	// 其存活条目由「零项段」清除（见 retireSegment）。
	Namespaces []string

	// BackoffBase / BackoffMax 是重连退避的起始值与上限。
	BackoffBase time.Duration
	BackoffMax  time.Duration

	// MetadataAttempts / MetadataRetryDelay 是流内 UPSERT 回查容器元数据的
	// 重试次数与间隔。重试就地完成，不放行后续事件：乱序放行会让 REMOVE 越过
	// UPSERT，C++ 侧先收到退出再收到加入，留下一个永不修正的幽灵角色。
	MetadataAttempts   int
	MetadataRetryDelay time.Duration

	// NamespacePollInterval 是重新核对 namespace 存在性的周期。
	// 删掉 namespace 不会让该 namespace 上的事件流报错，只能主动核对。
	NamespacePollInterval time.Duration

	// Log 是日志出口，为空则用默认出口。
	Log *slog.Logger
}

// DefaultConfig 返回缺省参数。
func DefaultConfig() Config {
	return Config{
		Address:               "/run/containerd/containerd.sock",
		Namespaces:            []string{"default", "k8s.io", "moby"},
		BackoffBase:           200 * time.Millisecond,
		BackoffMax:            30 * time.Second,
		MetadataAttempts:      3,
		MetadataRetryDelay:    100 * time.Millisecond,
		NamespacePollInterval: 30 * time.Second,
		Log:                   slog.Default(),
	}
}

// FrameWriter 是面向 C++ 的帧出口。Send 返回错误即连接不可用。
type FrameWriter interface {
	Send(frame *protocol.Frame) error
}

// Session 是一条 C++ 连接上的翻译会话。
//
// 生命周期：Run 阻塞直到 ctx 结束、出口不可用或调用方注入的 dial 永久失败。
// 期间对 containerd 的断连自行退避重连，不结束与 C++ 的连接——连接本身就是
// 源，断开即全部重来：重新订阅、重新快照、重新对账。
type Session struct {
	cfg  Config
	dial func(ctx context.Context) (source.Source, error)
	out  FrameWriter
	log  *slog.Logger

	// voids 是连续作废的段数：段开了场却没有收场。持续作废意味着对账没在发生，
	// 必须可见，否则静默退化成「只喂不结算」。
	voids int
}

// NewSession 构造会话，后端连接取自 cfg.Address。
func NewSession(cfg Config, out FrameWriter) *Session {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	session := &Session{cfg: cfg, out: out, log: cfg.Log}
	session.dial = func(ctx context.Context) (source.Source, error) {
		return source.Dial(ctx, cfg.Address)
	}
	return session
}

// WithDial 注入后端连接方式，供测试用替身。
func (s *Session) WithDial(dial func(ctx context.Context) (source.Source, error)) *Session {
	s.dial = dial
	return s
}

// Run 运行会话，直到 ctx 结束或出口不可用。
func (s *Session) Run(ctx context.Context) {
	attempt := 0
	for ctx.Err() == nil {
		src, err := s.dial(ctx)
		if err != nil {
			s.log.Warn("连接 containerd 失败", "err", err, "退避", backoff(s.cfg, attempt))
			if !sleep(ctx, backoff(s.cfg, attempt)) {
				return
			}
			attempt++
			continue
		}

		settled, err := s.serve(ctx, src)
		_ = src.Close()
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrOutputClosed) {
			s.log.Warn("与 C++ 的连接已断开，会话结束", "err", err)
			return
		}
		if settled {
			attempt = 0 // 后端跑完过一次完整快照，退避从头开始
		}
		if err != nil {
			s.log.Warn("containerd 会话结束，重连", "err", err, "退避", backoff(s.cfg, attempt))
		}
		if !sleep(ctx, backoff(s.cfg, attempt)) {
			return
		}
		attempt++
	}
}

// serve 跑一次完整的后端会话。
// @return settled 表示已跑完一次完整的快照段（退避可以重置）
func (s *Session) serve(ctx context.Context, src source.Source) (bool, error) {
	tr := translator.New(src)

	existing, err := src.Namespaces(ctx)
	if err != nil {
		return false, fmt.Errorf("枚举 namespace 失败: %w", err)
	}
	targets, retired := splitNamespaces(s.cfg.Namespaces, existing)

	// ① 先建流
	streams := newSubscriptionSet(src)
	defer streams.close()
	for _, namespace := range targets {
		if err := streams.add(ctx, namespace); err != nil {
			return false, fmt.Errorf("订阅 %s 失败: %w", namespace, err)
		}
	}

	// ② 已消失的 namespace：发一个零项段清除其残留条目。
	// 段的范围只含现存 namespace，这些残留不会被任何未来的段覆盖。
	for _, namespace := range retired {
		if err := s.retireSegment(src, namespace); err != nil {
			return false, err
		}
	}

	// ③ 后快照：逐 namespace 一段，任一段作废即整轮重走
	for _, namespace := range targets {
		if err := s.snapshotSegment(ctx, src, tr, namespace); err != nil {
			return false, fmt.Errorf("枚举 %s 失败，本段作废: %w", namespace, err)
		}
	}
	s.voids = 0

	// ④ 泵：段已全部收场，此时才消费流内事件
	if err := s.pump(ctx, src, tr, streams); err != nil {
		return true, err
	}
	return true, nil
}

// snapshotSegment 发一个 namespace 的快照段。
//
// 段起点先发 SnapshotBegin，枚举的任一步失败都不发 SnapshotEnd：不完整的
// 枚举不是权威状态，据它结算会把仍然存活但还没枚举到的角色误判为退出。
// 权威集取自运行中的 task 而非容器对象——已停止但未删除的容器据它构造会
// 被判「本段已见」而永不退出。
func (s *Session) snapshotSegment(
	ctx context.Context, src source.Source, tr *translator.Translator, namespace string,
) error {
	if err := s.send(&protocol.Frame{Body: &protocol.Frame_SnapshotBegin{
		SnapshotBegin: &protocol.SnapshotBegin{
			Source:         sourceName,
			BackendVersion: src.BackendVersion(),
			Namespaces:     []string{namespace},
		}}}); err != nil {
		return err
	}

	tasks, err := src.ListTasks(ctx, namespace)
	if err != nil {
		return s.voided(namespace, err)
	}

	count := 0
	for _, task := range tasks {
		observation, err := tr.Translate(ctx, translator.Decoded{
			Kind:        translator.KindUpsert,
			Namespace:   namespace,
			ContainerID: task.ID,
			Pid:         task.Pid,
			TimestampNs: time.Now().UnixNano(),
		})
		if err != nil {
			return s.voided(namespace, err)
		}
		observation.InSnapshot = true
		if err := s.sendObservation(observation); err != nil {
			return err
		}
		count++
	}

	return s.send(&protocol.Frame{Body: &protocol.Frame_SnapshotEnd{
		SnapshotEnd: &protocol.SnapshotEnd{Count: uint32(count)}}})
}

// retireSegment 为一个已消失的 namespace 发零项段，清除其残留条目。
func (s *Session) retireSegment(src source.Source, namespace string) error {
	s.log.Info("namespace 已消失，发零项段清除其残留条目", "namespace", namespace)
	if err := s.send(&protocol.Frame{Body: &protocol.Frame_SnapshotBegin{
		SnapshotBegin: &protocol.SnapshotBegin{
			Source:         sourceName,
			BackendVersion: src.BackendVersion(),
			Namespaces:     []string{namespace},
		}}}); err != nil {
		return err
	}
	return s.send(&protocol.Frame{Body: &protocol.Frame_SnapshotEnd{
		SnapshotEnd: &protocol.SnapshotEnd{}}})
}

// pump 消费流内事件，直到连接断开、订阅流报错或 ctx 结束。
func (s *Session) pump(
	ctx context.Context, src source.Source, tr *translator.Translator,
	streams *subscriptionSet,
) error {
	poll := time.NewTicker(s.cfg.NamespacePollInterval)
	defer poll.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err, ok := <-streams.errs:
			if !ok {
				return errors.New("订阅错误通道关闭")
			}
			return fmt.Errorf("订阅流断开: %w", err)

		case env, ok := <-streams.events:
			if !ok {
				return errors.New("事件通道关闭")
			}
			observation, err := s.translateLive(ctx, tr, env, streams)
			if err != nil {
				s.log.Warn("跳过一条事件", "topic", env.Topic, "err", err)
				continue
			}
			if observation == nil {
				continue
			}
			observation.InSnapshot = false
			if err := s.sendObservation(observation); err != nil {
				return err
			}

		case <-poll.C:
			if err := s.reconcileNamespaces(ctx, src, tr, streams); err != nil {
				return err
			}
		}
	}
}

// translateLive 翻译一条流内事件。
//
// 返回 nil 表示该事件不产生观察量：OOM 只记日志，已不跟踪的 namespace 的
// 事件一律丢弃（其残留条目已由零项段清除，再放行会留下范围外的幽灵）。
func (s *Session) translateLive(
	ctx context.Context, tr *translator.Translator, env *coreevents.Envelope,
	streams *subscriptionSet,
) (*protocol.Observation, error) {
	decoded, err := translator.Decode(env)
	if err != nil {
		return nil, err
	}
	if decoded.Kind == translator.KindOOM {
		s.log.Warn("容器主进程被 OOM killer 杀死",
			"namespace", decoded.Namespace, "container", decoded.ContainerID)
		return nil, nil
	}
	if !streams.tracked(decoded.Namespace) {
		return nil, nil
	}

	var lastErr error
	for range s.cfg.MetadataAttempts {
		observation, err := tr.Translate(ctx, decoded)
		if err == nil {
			return observation, nil
		}
		lastErr = err
		if !sleep(ctx, s.cfg.MetadataRetryDelay) {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("回查元数据失败 %d 次后放弃: %w", s.cfg.MetadataAttempts, lastErr)
}

// reconcileNamespaces 重新核对 namespace 的存在性，处理运行期的出现与消失。
//
// 存在的权威来源是后端的 namespace 列表，不是事件流：删掉 namespace 不会让
// 其上的事件流报错，等不到错误就只能主动核对。
func (s *Session) reconcileNamespaces(
	ctx context.Context, src source.Source, tr *translator.Translator,
	streams *subscriptionSet,
) error {
	existing, err := src.Namespaces(ctx)
	if err != nil {
		// 核对失败不是会话结束的理由：订阅流若真断了，会由 errs 通道报出来
		s.log.Warn("核对 namespace 失败", "err", err)
		return nil
	}
	live := make(map[string]bool, len(existing))
	for _, namespace := range existing {
		live[namespace] = true
	}

	for _, namespace := range s.cfg.Namespaces {
		if !streams.tracked(namespace) || live[namespace] {
			continue
		}
		// 先清残留、再停订阅：两者调换顺序时，停订阅前到达的事件会被丢弃，
		// 而它对应的条目随后又被零项段清掉，结果一致，但先清后停不必依赖这条
		if err := s.retireSegment(src, namespace); err != nil {
			return err
		}
		streams.remove(namespace)
	}

	for _, namespace := range s.cfg.Namespaces {
		if !live[namespace] || streams.tracked(namespace) {
			continue
		}
		s.log.Info("namespace 出现，开始跟踪", "namespace", namespace)
		if err := streams.add(ctx, namespace); err != nil {
			return fmt.Errorf("订阅 %s 失败: %w", namespace, err)
		}
		if err := s.snapshotSegment(ctx, src, tr, namespace); err != nil {
			return fmt.Errorf("枚举 %s 失败，本段作废: %w", namespace, err)
		}
	}
	return nil
}

// send 写出一帧，把出口错误归一成 ErrOutputClosed。
func (s *Session) send(frame *protocol.Frame) error {
	if err := s.out.Send(frame); err != nil {
		return fmt.Errorf("%w: %v", ErrOutputClosed, err)
	}
	return nil
}

func (s *Session) sendObservation(observation *protocol.Observation) error {
	return s.send(&protocol.Frame{Body: &protocol.Frame_Observation{
		Observation: observation}})
}

// voided 记一次段作废：段开了场却没有收场，C++ 侧不会结算。
func (s *Session) voided(namespace string, cause error) error {
	s.voids++
	s.log.Warn("快照段作废，不发 SnapshotEnd",
		"namespace", namespace, "连续作废", s.voids, "err", cause)
	return cause
}

// splitNamespaces 把配置的 namespace 分成两拨：本轮要跟踪的、已消失的。
func splitNamespaces(configured, existing []string) (targets, retired []string) {
	present := make(map[string]bool, len(existing))
	for _, namespace := range existing {
		present[namespace] = true
	}
	for _, namespace := range configured {
		if present[namespace] {
			targets = append(targets, namespace)
		} else {
			retired = append(retired, namespace)
		}
	}
	return targets, retired
}

// backoff 是第 attempt 次失败后的等待时长，指数增长并封顶。
func backoff(cfg Config, attempt int) time.Duration {
	delay := cfg.BackoffBase
	for range attempt {
		if delay >= cfg.BackoffMax {
			return cfg.BackoffMax
		}
		delay *= 2
	}
	return min(delay, cfg.BackoffMax)
}

// sleep 等待 d，ctx 结束时返回 false。
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
