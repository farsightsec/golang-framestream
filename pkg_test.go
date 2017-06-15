package framestream

import (
	"bytes"
	"net"
	"testing"
)

var FSContentType = []byte("protobuf:dnstap.Dnstap")

func TestUnidirectional(t *testing.T) {
	b := &bytes.Buffer{}

	enc, err := NewEncoder(b, &EncoderOptions{ContentType: FSContentType})
	if err != nil {
		t.Fatal(err)
		return
	}

	dec, err := NewDecoder(b, &DecoderOptions{ContentType: FSContentType})
	if err != nil {
		t.Fatal(err)
		return
	}

	testEncodeDecode(t, enc, dec)
}
func TestSocket(t *testing.T) {
	var enc *Encoder
	wait := make(chan bool)

	l, err := net.Listen("unix", "sock")
	if err != nil {
		t.Fatal(err)
		return
	}

	go func() {
		server, err := l.Accept()
		if err != nil {
			t.Fatal(err)
			return
		}

		opt := &DecoderOptions{
			ContentType:   FSContentType,
			Bidirectional: true,
		}
		dec, err := NewDecoder(server, opt)
		if err != nil {
			t.Fatal(err)
			return
		}

		testEncodeDecode(t, enc, dec)

		close(wait)
	}()

	if !t.Failed() {
		client, err := net.Dial("unix", "sock")
		if err != nil {
			t.Fatal(err)
			return
		}

		opt := &EncoderOptions{
			ContentType:   FSContentType,
			Bidirectional: true,
		}
		enc, err = NewEncoder(client, opt)
		if err != nil {
			t.Fatal(err)
			return
		}

		<-wait
	}

	if err := l.Close(); err != nil {
		t.Error(err)
	}
}

func testEncodeDecode(t *testing.T, enc *Encoder, dec *Decoder) {
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
			t.Errorf("frame %d: wanted: %s, got: %s", i, wants[i], string(frame))
		}
	}
}
