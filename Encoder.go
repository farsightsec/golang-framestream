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
	ContentType   []byte
	Bidirectional bool
}

type Encoder struct {
	writer *bufio.Writer
	opt    EncoderOptions
	buf    []byte
}

func openBiEncoder(rw io.ReadWriter, opt *EncoderOptions) error {
	// Write the ready control frame.
	cf := &ControlFrame{ControlType: CONTROL_READY}
	if opt.ContentType != nil {
		cf.ContentTypes = [][]byte{opt.ContentType}
	}
	if err := writeControlFrame(rw, cf); err != nil {
		return errors.Wrap(err, "write control ready")
	}

	// Wait for the accept control frame.
	cf, err := readControlFrameType(rw, CONTROL_ACCEPT)
	if err != nil {
		return errors.Wrap(err, "wait control accept")
	}

	// Check content type.
	matched := matchContentTypes(cf.ContentTypes, [][]byte{opt.ContentType})
	if len(matched) != 1 {
		return ErrContentTypeMismatch
	}

	return openEncoder(rw, opt)
}

func openEncoder(w io.Writer, opt *EncoderOptions) error {
	// Write the start control frame.
	cf := ControlFrame{ControlType: CONTROL_START}
	if opt.ContentType != nil {
		cf.ContentTypes = [][]byte{opt.ContentType}
	}
	return errors.Wrap(writeControlFrame(w, &cf),
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
	if opt.Bidirectional {
		r, ok := w.(io.Reader)
		if !ok {
			return nil, errors.New("need a io.Reader")
		}
		rw := struct {
			io.Reader
			io.Writer
		}{r, w}
		if err := openBiEncoder(rw, opt); err != nil {
			return nil, errors.Wrap(err, "bidirectional")
		}
	} else {
		if err := openEncoder(w, opt); err != nil {
			return nil, errors.Wrap(err, "unidirectional")
		}
	}
	return newEncoder(w, opt), nil
}

func (enc *Encoder) Close() error {
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
