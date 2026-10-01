package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func beginFrame() *Frame {
	return &Frame{Body: &Frame_SnapshotBegin{SnapshotBegin: &SnapshotBegin{
		Source:         "containerd-bridge",
		BackendVersion: "2.2.4",
		Namespaces:     []string{"k8s.io"},
	}}}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, beginFrame()); err != nil {
		t.Fatalf("写出失败: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("读出失败: %v", err)
	}
	begin := got.GetSnapshotBegin()
	if begin == nil || begin.BackendVersion != "2.2.4" || len(begin.Namespaces) != 1 {
		t.Fatalf("往返后内容不符: %v", got)
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("帧边界上的关闭应为 EOF，得到 %v", err)
	}
}

func TestFrameSequenceKeepsOrder(t *testing.T) {
	var buf bytes.Buffer
	frames := []*Frame{
		beginFrame(),
		{Body: &Frame_Observation{Observation: &Observation{
			Kind: Observation_UPSERT, ContainerId: "a", InSnapshot: true}}},
		{Body: &Frame_Observation{Observation: &Observation{
			Kind: Observation_UPSERT, ContainerId: "b", InSnapshot: true}}},
		{Body: &Frame_SnapshotEnd{SnapshotEnd: &SnapshotEnd{Count: 2}}},
	}
	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("写出失败: %v", err)
		}
	}

	var ids []string
	for range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("读出失败: %v", err)
		}
		if obs := got.GetObservation(); obs != nil {
			ids = append(ids, obs.GetContainerId())
		}
	}
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("顺序不符: %v", ids)
	}
}

func TestFrameHeaderOnly(t *testing.T) {
	// 帧读到一半即断开：不得把它当成一帧完整数据
	var buf bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 16)
	buf.Write(header[:])
	buf.Write([]byte{0x08})

	if _, err := ReadFrame(&buf); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("截断的帧应为 ErrUnexpectedEOF，得到 %v", err)
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxFrameBytes+1)
	buf.Write(header[:])

	if _, err := ReadFrame(&buf); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("超限的帧应被拒，得到 %v", err)
	}
}
