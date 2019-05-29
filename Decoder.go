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
	"io"
	"time"
)

type DecoderOptions struct {
	MaxPayloadSize uint32
	ContentType    []byte
	Bidirectional  bool
	Timeout        time.Duration
}

type Decoder struct {
	buf []byte
	r   *Reader
}

func NewDecoder(r io.Reader, opt *DecoderOptions) (*Decoder, error) {
	if opt == nil {
		opt = &DecoderOptions{}
	}
	if opt.MaxPayloadSize == 0 {
		opt.MaxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE
	}
	dr, err := NewReader(r, &ReaderOptions{
		Bidirectional: opt.Bidirectional,
		ContentType:   opt.ContentType,
		Timeout:       opt.Timeout,
	})
	if err != nil {
		return nil, err
	}
	dec := &Decoder{
		buf: make([]byte, opt.MaxPayloadSize),
		r:   dr,
	}
	return dec, nil
}

func (dec *Decoder) Decode() (frameData []byte, err error) {
	n, err := dec.r.Read(dec.buf)
	if err != nil {
		return nil, err
	}
	return dec.buf[:n], nil
}
