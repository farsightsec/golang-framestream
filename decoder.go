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

import "bufio"
import "bytes"
import "encoding/binary"
import "errors"
import "io"

const CONTROL_ACCEPT                = 0x01
const CONTROL_START                 = 0x02
const CONTROL_STOP                  = 0x03

const CONTROL_FIELD_CONTENT_TYPE    = 0x01

const DEFAULT_MAX_PAYLOAD_SIZE      = 1048576
const MAX_CONTROL_FRAME_SIZE        = 512

type DecoderOptions struct {
    MaxPayloadSize  uint32
    ContentType     []byte
}

type Decoder struct {
    ControlStart    []byte
    ControlStop     []byte
    ContentType     []byte
    buf             []byte
    opt             DecoderOptions
    rd              *bufio.Reader
    stopped         bool
}

var ErrContentTypeMismatch = errors.New("content type mismatch")
var ErrDataFrameTooLarge = errors.New("data frame too large")
var ErrShortRead = errors.New("short read")
var ErrDecode = errors.New("decoding error")

func NewDecoder(rd io.Reader, opt *DecoderOptions) (dec *Decoder, err error) {
    if opt == nil {
        opt = &DecoderOptions{}
    }
    if opt.MaxPayloadSize == 0 {
        opt.MaxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE
    }
    dec = &Decoder{
        buf:            make([]byte, opt.MaxPayloadSize),
        opt:            *opt,
        rd:             bufio.NewReader(rd),
    }

    // Read the start control frame.
    err = dec.readEscape()
    if err != nil {
        return
    }
    err = dec.readControlStart()
    if err != nil {
        return
    }

    // Check content type.
    if dec.ContentType != nil && dec.opt.ContentType != nil {
        if bytes.Compare(dec.ContentType, dec.opt.ContentType) != 0 {
            err = ErrContentTypeMismatch
            return
        }
    }

    return
}

func (dec *Decoder) readBE32() (val uint32, err error) {
    err = binary.Read(dec.rd, binary.BigEndian, &val)
    if err != nil {
        return 0, err
    }
    return
}

func (dec *Decoder) readEscape() (err error) {
    escape, err := dec.readBE32()
    if err != nil || escape != 0 {
        dec.stopped = true
        return
    }
    if escape != 0 {
        err = ErrDecode
        return
    }
    return
}

func (dec *Decoder) readControlFrame() (controlFrameData []byte,
                                        controlFrameType uint32,
                                        err error) {
    // Read the control frame length.
    controlFrameLen, err := dec.readBE32()
    if err != nil {
        return
    }

    // Enforce limits on control frame size.
    if controlFrameLen < 4 || controlFrameLen > MAX_CONTROL_FRAME_SIZE {
        err = ErrDecode
        return
    }

    // Read the control frame.
    controlFrameData = make([]byte, controlFrameLen)
    n, err := io.ReadFull(dec.rd, controlFrameData)
    if err != nil || uint32(n) != controlFrameLen {
        return
    }

    // Read the control frame type.
    p := bytes.NewBuffer(controlFrameData[0:4])
    err = binary.Read(p, binary.BigEndian, &controlFrameType)
    if err != nil {
        return
    }

    return
}

func (dec *Decoder) parseControlStart() {
    // Require that the control frame is long enough for three
    // 32-bit BE integers.
    if len(dec.ControlStart) < 12 {
        return
    }

    // Control type: 32-bit BE integer.
    controlFrameType := binary.BigEndian.Uint32(dec.ControlStart[0:4])
    if controlFrameType != CONTROL_START {
        return
    }

    // FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer.
    controlFieldType := binary.BigEndian.Uint32(dec.ControlStart[4:8])
    if controlFieldType != CONTROL_FIELD_CONTENT_TYPE {
        return
    }

    // Length of content type string: 32-bit BE integer.
    lenContentType := binary.BigEndian.Uint32(dec.ControlStart[8:12])
    if lenContentType > MAX_CONTROL_FRAME_SIZE {
        return
    }

    // The content type string itself: 'lenContentType' bytes.
    dec.ContentType = make([]byte, lenContentType)
    copy(dec.ContentType, dec.ControlStart[12:12+lenContentType])
}

func (dec *Decoder) readControlStart() (err error) {
    controlFrameData, controlFrameType, err := dec.readControlFrame()
    if err != nil {
        return
    }
    if controlFrameType != CONTROL_START {
        return ErrDecode
    }
    dec.ControlStart = controlFrameData
    dec.parseControlStart()
    return
}

func (dec *Decoder) readFrame(frameLen uint32) (err error) {
    // Enforce limits on frame size.
    if frameLen > dec.opt.MaxPayloadSize {
        err = ErrDataFrameTooLarge
        return
    }

    // Read the frame.
    n, err := io.ReadFull(dec.rd, dec.buf[0:frameLen])
    if err != nil || uint32(n) != frameLen {
        return
    }
    return
}

func (dec *Decoder) Decode() (frameData []byte, err error) {
    if dec.stopped {
        err = io.EOF
        return
    }

    // Read the frame length.
    frameLen, err := dec.readBE32()
    if err != nil {
        return
    }

    if frameLen == 0 {
        // This is a control frame.
        controlFrameData, controlFrameType, err := dec.readControlFrame()
        if controlFrameType == CONTROL_STOP {
            dec.ControlStop = controlFrameData
            dec.stopped = true
            return nil, io.EOF
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
