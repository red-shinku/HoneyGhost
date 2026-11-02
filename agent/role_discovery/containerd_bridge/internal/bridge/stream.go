package bridge

import (
	"context"
	"errors"
	"sync"

	coreevents "github.com/containerd/containerd/v2/core/events"

	"honeyghost/containerd_bridge/internal/source"
)

// mergedBuffer 是合并后的事件通道容量。
//
// 它同时是快照段的段内缓冲：段内不消费该通道，事件滞留在这里，因此不可能
// 有流内观察被排在段前面。窗口长度是枚举耗时（毫秒到秒级），期间的容器事件
// 量极小，容量足够。
const mergedBuffer = 1024

// subscriptionSet 是会话持有的订阅集合。
//
// 只有会话协程调用 add / remove，转发协程只把事件推进合并通道，不碰集合。
type subscriptionSet struct {
	src    source.Source
	events chan *coreevents.Envelope
	errs   chan error
	subs   map[string]*subscription
	wg     sync.WaitGroup
}

type subscription struct {
	cancel context.CancelFunc
}

func newSubscriptionSet(src source.Source) *subscriptionSet {
	return &subscriptionSet{
		src:    src,
		events: make(chan *coreevents.Envelope, mergedBuffer),
		errs:   make(chan error, len(source.Topics)),
		subs:   make(map[string]*subscription),
	}
}

// add 订阅一个 namespace 并开始把其事件并入合并通道。
func (s *subscriptionSet) add(ctx context.Context, namespace string) error {
	if _, ok := s.subs[namespace]; ok {
		return nil
	}

	subCtx, cancel := context.WithCancel(ctx)
	eventCh, errCh := s.src.Subscribe(subCtx, namespace, source.Topics...)
	s.subs[namespace] = &subscription{cancel: cancel}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case env := <-eventCh:
				select {
				case s.events <- env:
				case <-subCtx.Done():
					return
				}
			case err, ok := <-errCh:
				if !ok {
					err = errors.New("事件流结束")
				}
				select {
				case s.errs <- err:
				case <-subCtx.Done():
				}
				return
			case <-subCtx.Done():
				return
			}
		}
	}()
	return nil
}

// remove 停掉一个 namespace 的订阅。
//
// 不等待转发协程退出：它可能正阻塞在合并通道上，同步等待会死锁。退出前
// 可能仍推入若干事件，由消费侧按「该 namespace 已不在跟踪范围」丢弃。
func (s *subscriptionSet) remove(namespace string) {
	sub, ok := s.subs[namespace]
	if !ok {
		return
	}
	sub.cancel()
	delete(s.subs, namespace)
}

// tracked 报告该 namespace 是否仍在跟踪。
func (s *subscriptionSet) tracked(namespace string) bool {
	_, ok := s.subs[namespace]
	return ok
}

// close 停掉全部订阅。
func (s *subscriptionSet) close() {
	for namespace := range s.subs {
		s.subs[namespace].cancel()
	}
	s.subs = make(map[string]*subscription)
	s.wg.Wait()
}
