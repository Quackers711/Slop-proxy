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

// onRestore, when set, gets each tool input or reply text that had stand-ins,
// as the model wrote it and as the agent receives it, with what was restored.
// It feeds the traffic view.
type onRestore func(index int, model, agent string, trace []Rewrite)

func restoreInput(v *Vault, index int, tool, js string, on onRestore) string {
	if on == nil {
		return v.UnmaskToolInput(tool, js, nil)
	}
	var trace []Rewrite
	out := v.UnmaskToolInput(tool, js, &trace)
	on(index, js, out, trace)
	return out
}

func unmaskSSE(v *Vault, upstream io.ReadCloser, on onRestore) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(unmaskStream(v, upstream, pw, on)) }()
	return sseBody{pr, upstream}
}

// unmaskStream rewrites a Messages API event stream, putting real values back
// into tool inputs (what the harness writes and runs) and reply text (what the
// user reads; every request masks it again). Thinking stays as it came: it is
// signed, and sent back as is.
//
// Tool inputs are buffered per block and released whole at content_block_stop.
// Text is released up to its last whitespace, so it still streams while a
// stand-in split across text_delta chunks is still found (stand-ins never
// contain whitespace, except a [values] replacement someone wrote with spaces).
func unmaskStream(v *Vault, r io.Reader, w io.Writer, on onRestore) error {
	br := bufio.NewReader(r)
	st := &streamState{inputs: map[int]*strings.Builder{}, tools: map[int]string{}, text: map[int]*textBlock{}}
	var event []byte
	for {
		line, err := br.ReadBytes('\n')
		event = append(event, line...)
		if len(event) > 0 && (len(bytes.TrimRight(line, "\r\n")) == 0 || err != nil) {
			if werr := handleEvent(v, w, st, event, on); werr != nil {
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

type streamState struct {
	inputs map[int]*strings.Builder // tool input JSON so far, per block
	tools  map[int]string           // the tool's name, per block
	text   map[int]*textBlock
}

type textBlock struct {
	pending      string          // received, not yet released
	model, agent strings.Builder // all of it as the model wrote it, and as released
}

func handleEvent(v *Vault, w io.Writer, st *streamState, raw []byte, on onRestore) error {
	var d struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Delta struct {
			Type        string `json:"type"`
			PartialJSON string `json:"partial_json"`
			Text        string `json:"text"`
		} `json:"delta"`
		ContentBlock struct {
			Name string `json:"name"`
		} `json:"content_block"`
	}
	json.Unmarshal(sseData(raw), &d)
	switch d.Type {
	case "content_block_start":
		st.tools[d.Index] = d.ContentBlock.Name
	case "content_block_delta":
		switch d.Delta.Type {
		case "input_json_delta":
			if st.inputs[d.Index] == nil {
				st.inputs[d.Index] = &strings.Builder{}
			}
			st.inputs[d.Index].WriteString(d.Delta.PartialJSON)
			return nil
		case "text_delta":
			t := st.text[d.Index]
			if t == nil {
				t = &textBlock{}
				st.text[d.Index] = t
			}
			t.pending += d.Delta.Text
			cut := strings.LastIndexAny(t.pending, " \t\r\n") + 1
			if cut == 0 {
				return nil
			}
			out := t.pending[:cut]
			t.pending = t.pending[cut:]
			return t.release(v, w, d.Index, out)
		}
	case "content_block_stop":
		if b := st.inputs[d.Index]; b != nil {
			delete(st.inputs, d.Index)
			if err := writeDelta(w, d.Index, restoreInput(v, d.Index, st.tools[d.Index], b.String(), on)); err != nil {
				return err
			}
		}
		if t := st.text[d.Index]; t != nil {
			delete(st.text, d.Index)
			if err := t.release(v, w, d.Index, t.pending); err != nil {
				return err
			}
			if model, agent := t.model.String(), t.agent.String(); on != nil && model != agent {
				_, trace := v.UnmaskTextTrace(model)
				on(d.Index, model, agent, trace)
			}
		}
	}
	_, err := w.Write(raw)
	return err
}

// release sends s, with stand-ins restored, as one text_delta.
func (t *textBlock) release(v *Vault, w io.Writer, index int, s string) error {
	if s == "" {
		return nil
	}
	out := v.UnmaskText(s)
	t.model.WriteString(s)
	t.agent.WriteString(out)
	return writeEvent(w, map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]string{"type": "text_delta", "text": out}})
}

// unmaskToolInputs is the non-streaming counterpart of unmaskStream: tool
// inputs and text get real values back.
func unmaskToolInputs(v *Vault, body []byte, on onRestore) []byte {
	var msg map[string]json.RawMessage
	var content []map[string]json.RawMessage
	if json.Unmarshal(body, &msg) != nil || json.Unmarshal(msg["content"], &content) != nil {
		return body
	}
	for i, block := range content {
		if in, ok := block["input"]; ok {
			var tool string
			json.Unmarshal(block["name"], &tool)
			block["input"] = json.RawMessage(restoreInput(v, i, tool, string(in), on))
		}
		var typ, text string
		json.Unmarshal(block["type"], &typ)
		if typ == "text" && json.Unmarshal(block["text"], &text) == nil {
			out, trace := v.UnmaskTextTrace(text)
			if out != text {
				block["text"], _ = json.Marshal(out)
				if on != nil {
					on(i, text, out, trace)
				}
			}
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
	return writeEvent(w, map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]string{"type": "input_json_delta", "partial_json": partialJSON}})
}

// writeEvent writes one event (Encode's newline plus one more ends it).
func writeEvent(w io.Writer, ev map[string]any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(ev)
	_, err := fmt.Fprintf(w, "event: %s\ndata: %s\n", ev["type"], buf.Bytes())
	return err
}
