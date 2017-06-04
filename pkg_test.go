package framestream

import (
	"bytes"
	"io"
	"testing"
)

var FSContentType = []byte("protobuf:dnstap.Dnstap")

func TestEncodeDecode(t *testing.T) {
	b := &bytes.Buffer{}

	encOpt := &EncoderOptions{
		ContentType: FSContentType,
	}
	enc, err := NewEncoder(b, encOpt)
	if err != nil {
		t.Fatal(err)
		return
	}

	decOpt := &DecoderOptions{
		ContentType:   FSContentType,
		Bidirectional: false,
	}
	dec, err := NewDecoder(b, decOpt)
	if err != nil {
		t.Fatal(err)
		return
	}

	want := []string{"frame one", "two", "3"}
	for _, frame := range want {
		_, err := enc.Write([]byte(frame))
		if err != nil {
			t.Fatalf("encode failed: %s\n", err)
			return
		}
	}
	enc.Flush()
	enc.Close()

	i := 0
	for {
		frame, err := dec.Decode()
		if err != nil {
			if err != io.EOF {
				t.Errorf("decode failed: %s\n", err)
			}
			break
		}
		if i == len(want) {
			t.Errorf("too much frames")
			break
		}
		if string(frame) != want[i] {
			t.Errorf("frame %d: wanted: %s, got: %s", i, want[i], string(frame))
		}
		i++
	}
}
