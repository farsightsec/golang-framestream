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

type DecoderOptions struct {
	MaxPayloadSize uint32
	ContentType    []byte
	Bidirectional  bool
}

type Decoder struct {
	buf     []byte
	opt     DecoderOptions
	reader  *bufio.Reader
	writer  *bufio.Writer
	stopped bool
}

type ControlFrame struct {
	ControlType  uint32
	ContentTypes [][]byte
}

func openBiDecoder(rw io.ReadWriter, opt *DecoderOptions) error {

	// Read the ready control frame.
	cf, err := readControlFrameType(rw, CONTROL_READY)
	if err != nil {
		return err
	}

	// Check content type.
	matched := matchContentTypes(cf.ContentTypes, [][]byte{opt.ContentType})
	if len(matched) != 1 {
		return ErrContentTypeMismatch
	}

	// Send the accept control frame.
	cf = &ControlFrame{ControlType: CONTROL_ACCEPT, ContentTypes: matched}
	err = writeControlFrame(rw, cf)
	if err != nil {
		return err
	}

	return openDecoder(rw, opt)
}

func newDecoder(r io.Reader, opt *DecoderOptions) (dec *Decoder) {
	if opt == nil {
		opt = &DecoderOptions{}
	}
	if opt.MaxPayloadSize == 0 {
		opt.MaxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE
	}
	dec = &Decoder{
		buf:    make([]byte, opt.MaxPayloadSize),
		opt:    *opt,
		reader: bufio.NewReader(r),
		writer: nil,
	}
	return
}

func NewDecoder(r io.Reader, opt *DecoderOptions) (*Decoder, error) {
	if opt.Bidirectional {
		w, ok := r.(io.Writer)
		if !ok {
			return nil, ErrType
		}
		rw := struct {
			io.Reader
			io.Writer
		}{r, w}
		if err := openBiDecoder(rw, opt); err != nil {
			return nil, err
		}
	} else {
		if err := openDecoder(r, opt); err != nil {
			return nil, err
		}
	}
	return newDecoder(r, opt), nil
}
func openDecoder(r io.Reader, opt *DecoderOptions) error {

	// Read the start control frame.
	cf, err := readControlFrameType(r, CONTROL_START)
	if err != nil {
		return err
	}

	// Check content type.
	matched := matchContentTypes(cf.ContentTypes, [][]byte{opt.ContentType})
	if len(matched) != 1 {
		return ErrContentTypeMismatch
	}

	return nil
}

func readBE32(r io.Reader) (val uint32, err error) {
	err = binary.Read(r, binary.BigEndian, &val)
	if err != nil {
		return 0, err
	}
	return
}

func readEscape(r io.Reader) error {
	escape, err := readBE32(r)
	if err != nil {
		return err
	}
	if escape != 0 {
		return ErrDecode
	}
	return nil
}

func (dec *Decoder) readEscape() (err error) {
	err = readEscape(dec.reader)
	if err != nil {
		dec.stopped = true
	}
	return
}

func readControlFrame(reader io.Reader) (cf *ControlFrame, err error) {
	cf = new(ControlFrame)

	// Read the control frame length.
	controlFrameLen, err := readBE32(reader)
	if err != nil {
		return
	}

	// Enforce limits on control frame size.
	if controlFrameLen < 4 || controlFrameLen > MAX_CONTROL_FRAME_SIZE {
		err = ErrDecode
		return
	}

	// Read the control frame.
	controlFrameData := make([]byte, controlFrameLen)
	n, err := io.ReadFull(reader, controlFrameData)
	if err != nil || uint32(n) != controlFrameLen {
		return
	}

	// Read the control frame type.
	p := bytes.NewBuffer(controlFrameData[0:4])
	err = binary.Read(p, binary.BigEndian, &cf.ControlType)
	if err != nil {
		return
	}

	// Read the control fields.
	var pos uint32 = 8
	for pos < controlFrameLen {
		controlFieldType := binary.BigEndian.Uint32(controlFrameData[pos-4 : pos])
		switch controlFieldType {
		case CONTROL_FIELD_CONTENT_TYPE:
			{
				pos += 4
				if pos > controlFrameLen {
					return cf, ErrDecode
				}
				lenContentType := binary.BigEndian.Uint32(controlFrameData[pos-4 : pos])
				if lenContentType > MAX_CONTROL_FRAME_SIZE {
					return cf, ErrDecode
				}
				pos += lenContentType
				if pos > controlFrameLen {
					return cf, ErrDecode
				}
				contentType := make([]byte, lenContentType)
				copy(contentType, controlFrameData[pos-lenContentType:pos])
				cf.ContentTypes = append(cf.ContentTypes, contentType)
			}
		default:
			return cf, ErrDecode
		}
	}

	// Enforce limits on number of ContentType fields.
	lenContentTypes := len(cf.ContentTypes)
	switch cf.ControlType {
	case CONTROL_START:
		if lenContentTypes > 1 {
			return cf, ErrDecode
		}
	case CONTROL_STOP, CONTROL_FINISH:
		if lenContentTypes > 0 {
			return cf, ErrDecode
		}
	}

	return
}

func matchContentTypes(a [][]byte, b [][]byte) (c [][]byte) {
	matched := make([][]byte, 0, 0)
	for _, contentTypeA := range a {
		for _, contentTypeB := range b {
			if bytes.Compare(contentTypeA, contentTypeB) == 0 {
				matched = append(matched, contentTypeA)
			}
		}
	}
	return matched
}

func writeControlFrameBuf(w *bufio.Writer, cf *ControlFrame) error {
	if err := writeControlFrame(w, cf); err != nil {
		return err
	}
	return w.Flush()
}
func writeControlFrame(writer io.Writer, cf *ControlFrame) (err error) {
	// Escape: 32-bit BE integer. Zero: 4 bytes.
	// Frame length: 32-bit BE integer: 4 bytes.
	// Control type: 32-bit BE integer: 4 bytes.
	totalLen := 4 * 3

	for _, contentType := range cf.ContentTypes {
		totalLen += 4 + 4 + len(contentType)
	}

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
	err = binary.Write(buf, binary.BigEndian, uint32(cf.ControlType))
	if err != nil {
		return
	}

	for _, contentType := range cf.ContentTypes {
		// FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer.
		err = binary.Write(buf, binary.BigEndian, uint32(CONTROL_FIELD_CONTENT_TYPE))
		if err != nil {
			return
		}

		// Length of content type string: 32-bit BE integer.
		err = binary.Write(buf, binary.BigEndian, uint32(len(contentType)))
		if err != nil {
			return
		}

		// The content type string itself.
		_, err = buf.Write(contentType)
		if err != nil {
			return
		}
	}

	// Write the control frame.
	_, err = buf.WriteTo(writer)
	if err != nil {
		return
	}

	return nil
}

func readControlFrameType(r io.Reader, t uint32) (cf *ControlFrame, err error) {
	err = readEscape(r)
	if err != nil {
		return
	}
	cf, err = readControlFrame(r)
	if err != nil {
		return
	}
	if cf.ControlType != t {
		return cf, ErrDecode
	}
	return
}

func (dec *Decoder) readFrame(frameLen uint32) (err error) {
	// Enforce limits on frame size.
	if frameLen > dec.opt.MaxPayloadSize {
		err = ErrDataFrameTooLarge
		return
	}

	// Read the frame.
	n, err := io.ReadFull(dec.reader, dec.buf[0:frameLen])
	if err != nil || uint32(n) != frameLen {
		return
	}
	return
}

func (dec *Decoder) Decode() (frameData []byte, err error) {
	if dec.stopped {
		err = EOF
		return
	}

	// Read the frame length.
	frameLen, err := readBE32(dec.reader)
	if err != nil {
		return
	}
	if frameLen == 0 {
		// This is a control frame.
		cf, err := readControlFrame(dec.reader)
		if cf.ControlType == CONTROL_STOP {
			dec.stopped = true
			/* it has been commented in the C library so let's comment it
			if dec.opt.Bidirectional {
				ff := &ControlFrame{ControlType: CONTROL_FINISH}
				dec.sendControlFrame(ff)
			}*/
			return nil, EOF
		}
		if err != nil {
			return nil, err
		}

	} else {
		// This is a data frame.
		err = dec.readFrame(frameLen)
		if err != nil {
			return
		}
		frameData = dec.buf[0:frameLen]
	}

	return
}
