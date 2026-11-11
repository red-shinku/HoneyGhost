package cmd

import (
	"bufio"
	"bytes"
	"io"

	"honeyghost/cli/internal/model"
	"honeyghost/cli/internal/render"
)

// recordTarget 是记录流的一个输出目标。
type recordTarget struct {
	w       *bufio.Writer
	epipeOK bool // stdout：EPIPE 只停止本目标
	broken  bool // 已断开或已失败，不再写入
}

// write 写入一条记录并 flush 本目标。
func (t *recordTarget) write(p []byte) error {
	if t.broken {
		return nil
	}
	if _, err := t.w.Write(p); err != nil {
		return t.fail(err)
	}
	return t.flush()
}

// flush 刷新本目标的缓冲。
func (t *recordTarget) flush() error {
	if t.broken {
		return nil
	}
	return t.fail(t.w.Flush())
}

// fail 归类写入错误：epipeOK 目标的 EPIPE 只标记 broken 并吞掉。
func (t *recordTarget) fail(err error) error {
	if err == nil {
		return nil
	}
	if t.epipeOK && isEPIPE(err) {
		t.broken = true
		return nil
	}
	return err
}

// recordSink 用唯一渲染器把每条记录分发到多个目标。
//
// 渲染器只调用一次，复用同一块 buffer，因此 table 表头在每个目标各出现一次。
type recordSink struct {
	r       render.Renderer
	buf     bytes.Buffer
	targets []*recordTarget
}

// newRecordSink 按 file -> stdout 的顺序建立目标；nil 目标跳过。
func newRecordSink(r render.Renderer, stdout, file io.Writer) *recordSink {
	s := &recordSink{r: r}
	if file != nil {
		s.targets = append(s.targets, &recordTarget{w: bufio.NewWriter(file)})
	}
	if stdout != nil {
		s.targets = append(s.targets, &recordTarget{
			w:       bufio.NewWriter(stdout),
			epipeOK: true,
		})
	}
	return s
}

// Event 渲染一条事件并分发到所有未 broken 的目标。
func (s *recordSink) Event(ev model.Event) error {
	return s.emit(func(w io.Writer) error { return s.r.Event(w, ev) })
}

// Stats 渲染一条流统计并分发到所有未 broken 的目标。
func (s *recordSink) Stats(st model.StreamStats) error {
	return s.emit(func(w io.Writer) error { return s.r.StreamStats(w, st) })
}

// emit 渲染一次记录，再按目标顺序写入并 flush。
//
// file 目标的写/flush 错误原样返回；stdout 的 EPIPE 由 recordTarget 吞掉。
func (s *recordSink) emit(renderRecord func(io.Writer) error) error {
	s.buf.Reset()
	if err := renderRecord(&s.buf); err != nil {
		return err
	}
	record := s.buf.Bytes()
	for _, t := range s.targets {
		if err := t.write(record); err != nil {
			return err
		}
	}
	return nil
}

// Active 报告是否还有未 broken 的目标。
func (s *recordSink) Active() bool {
	for _, t := range s.targets {
		if !t.broken {
			return true
		}
	}
	return false
}

// Close 刷新所有未 broken 的目标，返回首个错误。
func (s *recordSink) Close() error {
	var first error
	for _, t := range s.targets {
		if err := t.flush(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
