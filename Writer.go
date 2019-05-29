/*
 * Copyright (c) 2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package framestream

import (
	"bufio"
	"encoding/binary"
	"io"
	"time"
)

type WriterOptions struct {
	ContentType   []byte
	Bidirectional bool
	Timeout       time.Duration
}

type Writer struct {
	writer *bufio.Writer
	reader *bufio.Reader
	opt    WriterOptions
	buf    []byte
}

func NewWriter(w io.Writer, opt *WriterOptions) (wr *Writer, err error) {
	if opt == nil {
		opt = &WriterOptions{}
	}
	w = timeoutWriter(w, opt)
	wr = &Writer{
		writer: bufio.NewWriter(w),
		opt:    *opt,
	}

	if opt.Bidirectional {
		r, ok := w.(io.Reader)
		if !ok {
			return nil, ErrType
		}
		wr.reader = bufio.NewReader(r)
		ready := ControlReady
		ready.SetContentType(opt.ContentType)
		if err = ready.EncodeFlush(wr.writer); err != nil {
			return
		}

		var accept ControlFrame
		if err = accept.DecodeTypeEscape(wr.reader, CONTROL_ACCEPT); err != nil {
			return
		}

		if !accept.MatchContentType(opt.ContentType) {
			return nil, ErrContentTypeMismatch
		}
	}

	// Write the start control frame.
	start := ControlStart
	start.SetContentType(opt.ContentType)
	err = start.EncodeFlush(wr.writer)
	if err != nil {
		return
	}

	return
}

func (wr *Writer) Close() (err error) {
	err = ControlStop.EncodeFlush(wr.writer)
	if err != nil || !wr.opt.Bidirectional {
		return
	}

	var finish ControlFrame
	return finish.DecodeTypeEscape(wr.reader, CONTROL_FINISH)
}

func (wr *Writer) Write(frame []byte) (n int, err error) {
	err = binary.Write(wr.writer, binary.BigEndian, uint32(len(frame)))
	if err != nil {
		return
	}
	return wr.writer.Write(frame)
}

func (wr *Writer) Flush() error {
	return wr.writer.Flush()
}
