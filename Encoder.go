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
	"bytes"
	"encoding/binary"
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

func NewEncoder(w io.Writer, opt *EncoderOptions) (enc *Encoder, err error) {
	if opt == nil {
		opt = &EncoderOptions{}
	}
	enc = &Encoder{
		writer: bufio.NewWriter(w),
		opt:    *opt,
	}

	// Write the start control frame.
	err = enc.writeControlStart()
	if err != nil {
		return
	}

	return
}

func (enc *Encoder) Close() error {
	return enc.writeControlStop()
}

func (enc *Encoder) writeControlStart() (err error) {
	totalLen := 0

	// Calculate the total amount of space needed for the control frame.

	// Escape: 32-bit BE integer. Zero.
	totalLen += 4

	// Frame length: 32-bit BE integer.
	totalLen += 4

	// Control type: 32-bit BE integer.
	totalLen += 4

	if enc.opt.ContentType != nil {
		// CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer.
		totalLen += 4

		// Length of content type string: 32-bit BE integer.
		totalLen += 4

		// The content type string itself.
		totalLen += len(enc.opt.ContentType)
	}

	// Allocate the storage for the control frame.
	buf := new(bytes.Buffer)

	// Now actually serialize the control frame.

	// Escape: 32-bit BE integer. Zero.
	err = binary.Write(buf, binary.BigEndian, uint32(0))
	if err != nil {
		return
	}

	// Frame length: 32-bit BE integer.
	//
	// This does not include the length of the escape frame or the length of
	// the frame length field itself, so subtract 2*4 bytes from the total
	// length.
	err = binary.Write(buf, binary.BigEndian, uint32(totalLen-2*4))
	if err != nil {
		return
	}

	// Control type: 32-bit BE integer.
	err = binary.Write(buf, binary.BigEndian, uint32(CONTROL_START))
	if err != nil {
		return
	}

	if enc.opt.ContentType != nil {
		// FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer.
		err = binary.Write(buf, binary.BigEndian, uint32(CONTROL_FIELD_CONTENT_TYPE))
		if err != nil {
			return
		}

		// Length of content type string: 32-bit BE integer.
		err = binary.Write(buf, binary.BigEndian, uint32(len(enc.opt.ContentType)))
		if err != nil {
			return
		}

		// The content type string itself.
		_, err = buf.Write(enc.opt.ContentType)
		if err != nil {
			return
		}
	}

	// Write the control frame.
	_, err = buf.WriteTo(enc.writer)
	if err != nil {
		return
	}

	return enc.Flush()
}

func (enc *Encoder) writeControlStop() (err error) {
	totalLen := 3 * 4
	buf := new(bytes.Buffer)

	// Escape: 32-bit BE integer. Zero.
	err = binary.Write(buf, binary.BigEndian, uint32(0))
	if err != nil {
		return
	}

	// Frame length: 32-bit BE integer.
	err = binary.Write(buf, binary.BigEndian, uint32(totalLen-2*4))
	if err != nil {
		return
	}

	// Control type: 32-bit BE integer.
	err = binary.Write(buf, binary.BigEndian, uint32(CONTROL_STOP))
	if err != nil {
		return
	}

	// Write the control frame.
	_, err = buf.WriteTo(enc.writer)
	if err != nil {
		return
	}

	return enc.Flush()
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
