package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type sseBody struct {
	*io.PipeReader
	upstream io.Closer
}

func (b sseBody) Close() error {
	b.upstream.Close()
	return b.PipeReader.Close()
}

func unmaskSSE(v *Vault, upstream io.ReadCloser) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(unmaskStream(v, upstream, pw)) }()
	return sseBody{pr, upstream}
}

// unmaskStream rewrites a Messages API event stream. Only tool inputs get real
// values back: they are what the harness writes and runs. Text and thinking stay
// as the agent saw them, so the user sees what the agent saw. Tool inputs are
// buffered per block and released whole at content_block_stop, so a token split
// across input_json_delta chunks is still found.
func unmaskStream(v *Vault, r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	inputs := map[int]*strings.Builder{}
	var event []byte
	for {
		line, err := br.ReadBytes('\n')
		event = append(event, line...)
		if len(event) > 0 && (len(bytes.TrimRight(line, "\r\n")) == 0 || err != nil) {
			if werr := handleEvent(v, w, inputs, event); werr != nil {
				return werr
			}
			event = nil
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func handleEvent(v *Vault, w io.Writer, inputs map[int]*strings.Builder, raw []byte) error {
	var d struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Delta struct {
			Type        string `json:"type"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
	}
	json.Unmarshal(sseData(raw), &d)
	switch d.Type {
	case "content_block_delta":
		if d.Delta.Type == "input_json_delta" {
			if inputs[d.Index] == nil {
				inputs[d.Index] = &strings.Builder{}
			}
			inputs[d.Index].WriteString(d.Delta.PartialJSON)
			return nil
		}
	case "content_block_stop":
		if b := inputs[d.Index]; b != nil {
			delete(inputs, d.Index)
			if err := writeDelta(w, d.Index, v.UnmaskInput(b.String())); err != nil {
				return err
			}
		}
	}
	_, err := w.Write(raw)
	return err
}

// unmaskToolInputs is the non-streaming counterpart of unmaskStream.
func unmaskToolInputs(v *Vault, body []byte) []byte {
	var msg map[string]json.RawMessage
	var content []map[string]json.RawMessage
	if json.Unmarshal(body, &msg) != nil || json.Unmarshal(msg["content"], &content) != nil {
		return body
	}
	for _, block := range content {
		if in, ok := block["input"]; ok {
			block["input"] = json.RawMessage(v.UnmaskInput(string(in)))
		}
	}
	msg["content"], _ = json.Marshal(content)
	out, err := json.Marshal(msg)
	if err != nil {
		return body
	}
	return out
}

func sseData(raw []byte) []byte {
	var data [][]byte
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if rest, ok := bytes.CutPrefix(bytes.TrimRight(line, "\r"), []byte("data:")); ok {
			data = append(data, bytes.TrimPrefix(rest, []byte(" ")))
		}
	}
	return bytes.Join(data, []byte("\n"))
}

func writeDelta(w io.Writer, index int, partialJSON string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]string{"type": "input_json_delta", "partial_json": partialJSON}})
	_, err := fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n", buf.Bytes())
	return err
}
