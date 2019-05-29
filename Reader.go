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
	"io/ioutil"
	"time"
)

type ReaderOptions struct {
	ContentType   []byte
	Bidirectional bool
	Timeout       time.Duration
}

type Reader struct {
	contentType   []byte
	bidirectional bool
	r             *bufio.Reader
	w             *bufio.Writer
	stopped       bool
}

func NewReader(r io.Reader, opt *ReaderOptions) (*Reader, error) {
	if opt == nil {
		opt = &ReaderOptions{}
	}
	tr := timeoutReader(r, opt)
	reader := &Reader{
		bidirectional: opt.Bidirectional,
		r:             bufio.NewReader(tr),
		w:             nil,
	}

	var cf ControlFrame
	if opt.Bidirectional {
		w, ok := tr.(io.Writer)
		if !ok {
			return nil, ErrType
		}
		reader.w = bufio.NewWriter(w)

		// Read the ready control frame.
		err := cf.DecodeTypeEscape(reader.r, CONTROL_READY)
		if err != nil {
			return nil, err
		}

		// Check content type.
		if !cf.MatchContentType(opt.ContentType) {
			return nil, ErrContentTypeMismatch
		}

		// Send the accept control frame.
		accept := ControlAccept
		accept.SetContentType(opt.ContentType)
		err = accept.EncodeFlush(reader.w)
		if err != nil {
			return nil, err
		}
	}

	// Read the start control frame.
	err := cf.DecodeTypeEscape(reader.r, CONTROL_START)
	if err != nil {
		return nil, err
	}

	// Disable the read timeout to prevent killing idle connections.
	disableReadTimeout(tr)

	// Check content type.
	if !cf.MatchContentType(opt.ContentType) {
		return nil, ErrContentTypeMismatch
	}

	return reader, nil
}

func (r *Reader) Read(b []byte) (n int, err error) {
	if r.stopped {
		return 0, EOF
	}

	for n == 0 {
		n, err = r.readFrame(b)
		if err != nil {
			return
		}
	}

	return
}

func (r *Reader) readFrame(b []byte) (int, error) {
	// Read the frame length.
	var frameLen uint32
	err := binary.Read(r.r, binary.BigEndian, &frameLen)
	if err != nil {
		return 0, err
	}

	if frameLen > uint32(len(b)) {
		io.CopyN(ioutil.Discard, r.r, int64(frameLen))
		return 0, ErrDataFrameTooLarge
	}

	if frameLen == 0 {
		// This is a control frame.
		var cf ControlFrame
		err = cf.Decode(r.r)
		if err != nil {
			return 0, err
		}
		if cf.ControlType == CONTROL_STOP {
			r.stopped = true
			if r.bidirectional {
				ff := &ControlFrame{ControlType: CONTROL_FINISH}
				err = ff.EncodeFlush(r.w)
				if err != nil {
					return 0, err
				}
			}
			return 0, EOF
		}
		return 0, err
	}

	return io.ReadFull(r.r, b[0:frameLen])
}
