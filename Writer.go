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
	ContentTypes  [][]byte
	Bidirectional bool
	Timeout       time.Duration
}

type Writer struct {
	contentType []byte
	w           *bufio.Writer
	r           *bufio.Reader
	opt         WriterOptions
	buf         []byte
}

func NewWriter(w io.Writer, opt *WriterOptions) (writer *Writer, err error) {
	if opt == nil {
		opt = &WriterOptions{}
	}
	w = timeoutWriter(w, opt)
	writer = &Writer{
		w:   bufio.NewWriter(w),
		opt: *opt,
	}

	if opt.ContentTypes != nil {
		writer.contentType = opt.ContentTypes[0]
	}

	if opt.Bidirectional {
		r, ok := w.(io.Reader)
		if !ok {
			return nil, ErrType
		}
		writer.r = bufio.NewReader(r)
		ready := ControlReady
		ready.SetContentTypes(opt.ContentTypes)
		if err = ready.EncodeFlush(writer.w); err != nil {
			return
		}

		var accept ControlFrame
		if err = accept.DecodeTypeEscape(writer.r, CONTROL_ACCEPT); err != nil {
			return
		}

		if t, ok := accept.ChooseContentType(opt.ContentTypes); ok {
			writer.contentType = t
		} else {
			return nil, ErrContentTypeMismatch
		}
	}

	// Write the start control frame.
	start := ControlStart
	start.SetContentType(writer.contentType)
	err = start.EncodeFlush(writer.w)
	if err != nil {
		return
	}

	return
}

func (w *Writer) ContentType() []byte {
	return w.contentType
}

func (w *Writer) Close() (err error) {
	err = ControlStop.EncodeFlush(w.w)
	if err != nil || !w.opt.Bidirectional {
		return
	}

	var finish ControlFrame
	return finish.DecodeTypeEscape(w.r, CONTROL_FINISH)
}

func (w *Writer) Write(frame []byte) (n int, err error) {
	err = binary.Write(w.w, binary.BigEndian, uint32(len(frame)))
	if err != nil {
		return
	}
	return w.w.Write(frame)
}

func (w *Writer) Flush() error {
	return w.w.Flush()
}
