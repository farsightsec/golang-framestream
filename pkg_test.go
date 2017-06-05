package framestream

import (
	"bytes"
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

	wants := []string{"frame one", "two", "3"}
	for _, frame := range wants {
		_, err := enc.Write([]byte(frame))
		if err != nil {
			t.Fatalf("encode failed: %s\n", err)
			return
		}
	}
	enc.Flush()
	enc.Close()

	for i, want := range wants {
		frame, err := dec.Decode()
		if err != nil {
			t.Errorf("decode failed: %s\n", err)
		}
		if string(frame) != want {
			t.Errorf("frame %d: wanted: %s, got: %s", i, want[i], string(frame))
		}
	}
}
