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
	"github.com/pkg/errors"
	"io"
)

type DecoderOptions struct {
	MaxPayloadSize uint32
	ContentType    []byte
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

func NewBidirectionalDecoder(rw io.ReadWriter, opt *DecoderOptions) (dec *Decoder, err error) {
	dec = newDecoder(rw, opt)

	// Read the ready control frame.
	cf, err := dec.readControlFrameType(CONTROL_READY)
	if err != nil {
		return
	}

	// Check content type.
	matched := MatchContentTypes(cf.ContentTypes, [][]byte{dec.opt.ContentType})
	if len(matched) != 1 {
		return dec, ErrContentTypeMismatch
	}

	// Send the accept control frame.
	cf = &ControlFrame{ControlType: CONTROL_ACCEPT, ContentTypes: matched}
	err = writeControlFrame(rw, cf)
	if err != nil {
		err = errors.Wrap(err, "send the accept control frame")
		return
	}

	return dec, startDecoder(dec)
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
	dec := newDecoder(r, opt)
	return dec, startDecoder(dec)
}
func startDecoder(dec *Decoder) error {

	// Read the start control frame.
	cf, err := dec.readControlFrameType(CONTROL_START)
	if err != nil {
		return errors.Wrap(err, "read control start")
	}

	// Check content type.
	matched := MatchContentTypes(cf.ContentTypes, [][]byte{dec.opt.ContentType})
	if len(matched) != 1 {
		return ErrContentTypeMismatch
	}

	return nil
}

func ReadBE32(r io.Reader) (val uint32, err error) {
	err = binary.Read(r, binary.BigEndian, &val)
	if err != nil {
		return 0, err
	}
	return
}

func (dec *Decoder) readBE32() (val uint32, err error) {
	return ReadBE32(dec.reader)
}

func readEscape(r io.Reader) error {
	escape, err := ReadBE32(r)
	if err != nil {
		return err
	}
	if escape != 0 {
		return errors.New("escape != 0")
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

func (dec *Decoder) readControlFrame() (cf *ControlFrame, err error) {
	return readControlFrame(dec.reader)
}

func readControlFrame(reader io.Reader) (cf *ControlFrame, err error) {
	cf = new(ControlFrame)

	// Read the control frame length.
	controlFrameLen, err := ReadBE32(reader)
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

func MatchContentTypes(a [][]byte, b [][]byte) (c [][]byte) {
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
	return errors.Wrap(w.Flush(), "flush")
}
func writeControlFrame(writer io.Writer, cf *ControlFrame) (err error) {
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
		return cf, errors.Errorf("wrong control frame type, got: %d, want: %d", cf.ControlType, t)
	}
	return
}
func (dec *Decoder) readControlFrameType(t uint32) (cf *ControlFrame, err error) {
	cf, err = readControlFrameType(dec.reader, t)
	if err != nil {
		dec.stopped = true
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
	frameLen, err := dec.readBE32()
	if err != nil {
		return
	}
	if frameLen == 0 {
		// This is a control frame.
		cf, err := dec.readControlFrame()
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
