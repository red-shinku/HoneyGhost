// Package protocol 承载翻译进程与 C++ 发现器之间的帧编解码。
//
// 分帧：4 字节大端长度前缀 + 序列化的 Frame。长度前缀只表达一帧的字节数，
// 别处一律不解释它；一条连接上只有帧序列，没有请求应答配对。
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

const (
	// maxFrameBytes 是单帧上限。容器数量级为百、标签为 KB 级，正常帧远小于
	// 该上限；它只用来挡住畸形长度前缀导致的无界分配。
	maxFrameBytes = 4 << 20
)

// ErrFrameTooLarge 表示长度前缀超出自认的上限。
var ErrFrameTooLarge = errors.New("帧长度超出上限")

// WriteFrame 写出一帧。写入失败即连接不可用，调用方应结束会话。
func WriteFrame(w io.Writer, frame *Frame) error {
	payload, err := proto.Marshal(frame)
	if err != nil {
		return fmt.Errorf("序列化帧失败: %w", err)
	}
	if len(payload) > maxFrameBytes {
		return ErrFrameTooLarge
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// ReadFrame 读出一帧。
//
// 对端在帧边界上关闭连接时返回 io.EOF；帧读到一半即断开时返回
// io.ErrUnexpectedEOF。两种情况都表示会话结束。
func ReadFrame(r io.Reader) (*Frame, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(header[:])
	if size > maxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	if size == 0 {
		return nil, errors.New("空帧")
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	frame := &Frame{}
	if err := proto.Unmarshal(payload, frame); err != nil {
		return nil, fmt.Errorf("解析帧失败: %w", err)
	}
	return frame, nil
}
