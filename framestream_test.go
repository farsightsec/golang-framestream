package framestream_test

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	framestream "github.com/farsightsec/golang-framestream"
)

func testDecoder(t *testing.T, dec *framestream.Decoder, nframes int) {
	i := 1
	for {
		tf, err := dec.Decode()
		if err != nil {
			if i < nframes+1 {
				t.Fatalf("testDecoder(%d): %v", i, err)
			}
			if err != framestream.EOF {
				t.Fatalf("unexpected error: %v != EOF", err)
			}
			return
		}
		if i > nframes {
			t.Errorf("extra frame received: %d", i)
		}
		f := make([]byte, i)
		if bytes.Compare(tf, f) != 0 {
			t.Errorf("testDecoder: received %v != %v", tf, f)
		}
		i++
	}
}

func TestUnidirectional(t *testing.T) {
	buf := new(bytes.Buffer)
	enc, err := framestream.NewEncoder(buf, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i < 10; i++ {
		b := make([]byte, i)
		if _, err = enc.Write(b); err != nil {
			t.Error(err)
		}
	}
	enc.Close()

	dec, err := framestream.NewDecoder(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	testDecoder(t, dec, 9)
}

func TestBidirectional(t *testing.T) {
	client, server := net.Pipe()

	go func() {
		dec, err := framestream.NewDecoder(server,
			&framestream.DecoderOptions{
				Bidirectional: true,
			})

		if err != nil {
			t.Fatal(err)
		}
		testDecoder(t, dec, 9)
	}()

	enc, err := framestream.NewEncoder(client,
		&framestream.EncoderOptions{
			Bidirectional: true,
		})
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i < 10; i++ {
		b := make([]byte, i)
		if _, err := enc.Write(b); err != nil {
			t.Error(err)
		}
	}
	enc.Close()
}

func TestContentTypeMismatch(t *testing.T) {
	buf := new(bytes.Buffer)

	enc, err := framestream.NewEncoder(buf,
		&framestream.EncoderOptions{
			ContentType: []byte("test"),
		})
	if err != nil {
		t.Fatal(err)
	}
	enc.Write([]byte("hello, world"))
	enc.Close()

	_, err = framestream.NewDecoder(buf,
		&framestream.DecoderOptions{
			ContentType: []byte("wrong"),
		})
	if err != framestream.ErrContentTypeMismatch {
		t.Errorf("expected %v, received %v",
			framestream.ErrContentTypeMismatch,
			err)
	}
}

func TestOversizeFrame(t *testing.T) {
	buf := new(bytes.Buffer)
	enc, err := framestream.NewEncoder(buf, nil)
	if err != nil {
		t.Fatal(err)
	}

	enc.Write(make([]byte, 15))
	enc.Close()

	dec, err := framestream.NewDecoder(buf,
		&framestream.DecoderOptions{
			MaxPayloadSize: 10,
		})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dec.Decode()
	if err != framestream.ErrDataFrameTooLarge {
		t.Errorf("data frame too large, received %v", err)
	}
}

func testNew(t *testing.T, bidirectional bool, timeout time.Duration) {
	client, server := net.Pipe()
	wg := &sync.WaitGroup{}
	wg.Add(2)
	done := make(chan bool)

	defer client.Close()
	defer server.Close()

	go func() {
		_, err := framestream.NewDecoder(server,
			&framestream.DecoderOptions{
				Bidirectional: bidirectional,
				Timeout:       timeout,
			})

		if err != nil {
			t.Log("decoder error: ", err)
		}
		wg.Done()
	}()

	go func() {
		_, err := framestream.NewEncoder(client,
			&framestream.EncoderOptions{
				Bidirectional: bidirectional,
				Timeout:       timeout,
			})
		if err != nil {
			t.Log("encoder error: ", err)
		}
		wg.Done()
	}()

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Time's up.")
	}
}

func TestNewBidirectional(t *testing.T) {
	testNew(t, true, 0)
}

func TestNewUnidirectional(t *testing.T) {
	testNew(t, false, 0)
}

func TestNewBidirectionalTimeout(t *testing.T) {
	testNew(t, true, time.Second)
}

func testNegotiate(t *testing.T, rtypes, wtypes [][]byte, expected []byte, ok bool) {
	wc, rc := net.Pipe()
	done := make(chan error)
	defer wc.Close()
	defer rc.Close()
	go func() {
		w, err := framestream.NewWriter(wc, &framestream.WriterOptions{
			Bidirectional: true,
			ContentTypes:  wtypes,
		})
		defer close(done)
		if err != nil {
			done <- err
			wc.Close()
			return
		}
		if bytes.Compare(expected, w.ContentType()) != 0 {
			done <- fmt.Errorf("writer content type %s != %s",
				w.ContentType(), expected)
		}
	}()

	r, err := framestream.NewReader(rc, &framestream.ReaderOptions{
		Bidirectional: true,
		ContentTypes:  rtypes,
	})
	if err != nil {
		if ok {
			t.Errorf("NewReader error: %v", err)
		}
		rc.Close()
	} else {
		if !ok {
			t.Errorf("NewReader did not fail as expected")
		}
		if bytes.Compare(expected, r.ContentType()) != 0 {
			t.Errorf("reader content type %s != %s",
				r.ContentType(), expected)
		}
	}
	err = <-done
	if ok && err != nil {
		t.Errorf("Writer error: %v", err)
	}
	if !ok && err == nil {
		t.Errorf("Writer did not fail as expected")
	}
}

func contentTypes(types ...string) [][]byte {
	b := make([][]byte, 0)
	for _, t := range types {
		b = append(b, []byte(t))
	}
	return b
}

func TestContentTypes(t *testing.T) {
	t.Log("reader: nil, writer: nil, expect: nil")
	testNegotiate(t, nil, nil, nil, true)
	t.Log("reader: type1, writer: type1, expect: type1")
	testNegotiate(t,
		contentTypes("type1"),
		contentTypes("type1"),
		[]byte("type1"), true)
	t.Log("reader: type1, writer: type2, expect: error")
	testNegotiate(t,
		contentTypes("type1"),
		contentTypes("type2"),
		nil, false)
	t.Log("reader: type1, type2, type3, writer: type4, type3, type2, expect: type2")
	testNegotiate(t,
		contentTypes("type1", "type2", "type3"),
		contentTypes("type4", "type3", "type2"),
		[]byte("type2"), true)
}
