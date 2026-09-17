package peer_test

import (
	"bytes"
	"testing"

	"github.com/natalie-o-perret/go-torrent/peer"
)

func FuzzFrameCodec(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 5, byte(peer.MsgHave), 0, 0, 0, 1})
	f.Add([]byte{0, 0, 0, 2, byte(peer.MsgChoke), 1})
	f.Add([]byte{0, 1, 0, 0})

	f.Fuzz(func(t *testing.T, wire []byte) {
		codec := peer.Codec{MaxFrameSize: 64 << 10}
		message, err := codec.ReadMessage(bytes.NewReader(wire))
		if err != nil {
			return
		}
		var encoded bytes.Buffer
		if message == nil {
			err = codec.WriteKeepalive(&encoded)
		} else {
			err = codec.WriteMessage(&encoded, message)
		}
		if err != nil {
			t.Fatalf("accepted frame could not be encoded: %v", err)
		}
		if _, err := codec.ReadMessage(&encoded); err != nil {
			t.Fatalf("encoded frame could not be decoded: %v", err)
		}
	})
}

func FuzzMessagePayloadParsers(f *testing.F) {
	f.Add(byte(peer.MsgHave), peer.FormatHave(1))
	f.Add(byte(peer.MsgRequest), peer.FormatRequest(1, 0, peer.MaxBlockLength))
	piece, _ := peer.FormatPiece(1, 0, []byte("block"))
	f.Add(byte(peer.MsgPiece), piece)
	port, _ := peer.FormatPort(6881)
	f.Add(byte(peer.MsgPort), port)
	f.Add(byte(peer.MsgExtended), []byte{0, 'd', 'e'})
	f.Add(byte(peer.MsgHashRequest), make([]byte, 48))
	f.Add(byte(255), []byte("future"))

	f.Fuzz(func(t *testing.T, id byte, payload []byte) {
		if len(payload) > 64<<10 {
			return
		}
		message := &peer.Message{ID: peer.MessageID(id), Payload: payload}
		if err := peer.ValidateMessage(message); err != nil {
			return
		}
		var encoded bytes.Buffer
		codec := peer.Codec{MaxFrameSize: 64 << 10}
		if err := codec.WriteMessage(&encoded, message); err != nil {
			t.Fatalf("accepted payload could not be framed: %v", err)
		}
		if _, err := codec.ReadMessage(&encoded); err != nil {
			t.Fatalf("framed payload could not be parsed: %v", err)
		}
	})
}

func FuzzExtensionParsers(f *testing.F) {
	f.Add([]byte("de"))
	f.Add([]byte("d8:msg_typei0e5:piecei0ee"))
	pexSeed := append([]byte("d5:added6:"), []byte{192, 0, 2, 1, 0x1a, 0xe1}...)
	f.Add(append(pexSeed, 'e'))
	f.Add([]byte("not bencode"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 64<<10 {
			return
		}
		if handshake, err := peer.DecodeExtensionHandshake(payload); err == nil {
			if _, err := handshake.Encode(); err != nil {
				t.Fatalf("accepted extension handshake could not be encoded: %v", err)
			}
		}
		if message, err := peer.DecodeMetadataMessage(payload, 64<<10); err == nil {
			if _, err := message.Encode(); err != nil {
				t.Fatalf("accepted metadata message could not be encoded: %v", err)
			}
		}
		if message, err := peer.DecodePEXMessage(payload, peer.PEXLimits{MaxAdded: 100, MaxDropped: 100}); err == nil {
			if _, err := message.Encode(peer.PEXLimits{MaxAdded: 100, MaxDropped: 100}); err != nil {
				t.Fatalf("accepted PEX message could not be encoded: %v", err)
			}
		}
	})
}
