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
	"github.com/pkg/errors"
	"io"
)

type EncoderOptions struct {
	ContentType []byte
}

type Encoder struct {
	writer *bufio.Writer
	opt    EncoderOptions
	buf    []byte
}

func NewBidirectionalEncoder(rw io.ReadWriter, opt *EncoderOptions) (enc *Encoder, err error) {
	enc = newEncoder(rw, opt)

	// Write the ready control frame.
	cf := &ControlFrame{ControlType: CONTROL_READY}
	if opt.ContentType != nil {
		cf.ContentTypes = [][]byte{opt.ContentType}
	}
	if err = writeControlFrameBuf(enc.writer, cf); err != nil {
		err = errors.Wrap(err, "write the ready control frame")
		return
	}

	// Wait for the accept control frame.
	cf, err = readControlFrameType(rw, CONTROL_ACCEPT)
	if err != nil {
		err = errors.Wrap(err, "wait accept control frame")
		return
	}

	// Check content type.
	matched := MatchContentTypes(cf.ContentTypes, [][]byte{opt.ContentType})
	if len(matched) != 1 {
		return enc, ErrContentTypeMismatch
	}

	return enc, startEncoder(enc)
}

// Write the start control frame.
func startEncoder(enc *Encoder) error {
	return errors.Wrap(enc.writeControlStart(),
		"write the start control frame")
}
func newEncoder(w io.Writer, opt *EncoderOptions) (enc *Encoder) {
	if opt == nil {
		opt = &EncoderOptions{}
	}
	enc = &Encoder{
		writer: bufio.NewWriter(w),
		opt:    *opt,
	}
	return enc
}

func NewEncoder(w io.Writer, opt *EncoderOptions) (*Encoder, error) {
	enc := newEncoder(w, opt)
	return enc, startEncoder(enc)

}

func (enc *Encoder) Close() error {
	return enc.writeControlStop()
}

func (enc *Encoder) writeControlStart() (err error) {
	cf := ControlFrame{ControlType: CONTROL_START}
	if enc.opt.ContentType != nil {
		cf.ContentTypes = [][]byte{enc.opt.ContentType}
	}
	return writeControlFrameBuf(enc.writer, &cf)
}

func (enc *Encoder) writeControlStop() (err error) {
	cf := ControlFrame{ControlType: CONTROL_STOP}
	return writeControlFrameBuf(enc.writer, &cf)
}

func (enc *Encoder) Write(frame []byte) (n int, err error) {
	err = binary.Write(enc.writer, binary.BigEndian, uint32(len(frame)))
	if err != nil {
		return
	}
	return enc.writer.Write(frame)
}

func (enc *Encoder) Flush() error {
	return enc.writer.Flush()
}
