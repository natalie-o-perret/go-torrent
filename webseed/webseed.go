// Package webseed reads BitTorrent pieces from BEP 19 HTTP and HTTPS seeds.
package webseed

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/storage"
)

const v2BlockLength int64 = 16 << 10

// ErrorClass describes whether and how a web-seed operation may be retried.
type ErrorClass string

const (
	ClassUnknown   ErrorClass = ""
	ClassPermanent ErrorClass = "permanent"
	ClassTransient ErrorClass = "transient"
	ClassBusy      ErrorClass = "busy"
	ClassCanceled  ErrorClass = "canceled"
	ClassIntegrity ErrorClass = "integrity"
	ClassDisabled  ErrorClass = "disabled"
)

// Error is a classified web-seed failure.
type Error struct {
	Class      ErrorClass
	Op         string
	URL        string
	StatusCode int
	Err        error
}

func (e *Error) Error() string {
	if e == nil {
		return "webseed: <nil>"
	}
	message := "webseed: " + e.Op
	if e.URL != "" {
		message += " " + e.URL
	}
	if e.StatusCode != 0 {
		message += fmt.Sprintf(": HTTP status %d", e.StatusCode)
	}
	if e.Err != nil {
		message += ": " + e.Err.Error()
	}
	return message
}

// Unwrap returns the underlying failure.
func (e *Error) Unwrap() error { return e.Err }

// ClassOf returns the web-seed classification of err.
func ClassOf(err error) ErrorClass {
	var classified *Error
	if errors.As(err, &classified) {
		return classified.Class
	}
	return ClassUnknown
}

// IsRetryable reports whether retrying with the same source may succeed.
func IsRetryable(err error) bool {
	class := ClassOf(err)
	return class == ClassTransient || class == ClassBusy
}

type remoteFile struct {
	url    string
	length int64
}

type pieceCheck struct {
	v1     metainfo.Hash
	v2     metainfo.HashV2
	v2Span int64
}

// Source maps checked storage-layout ranges to one BEP 19 URL.
// Source is safe for concurrent use when its http.Client is safe for
// concurrent use.
type Source struct {
	client *http.Client
	layout *storage.Layout
	files  map[string]remoteFile
	checks map[storage.Protocol][]pieceCheck
	url    string
	bad    atomic.Bool
}

// NewSource validates meta and rawURL. Multi-file URLs must be base URLs ending
// in a slash. A single-file URL ending in a slash has the torrent name appended;
// otherwise it is treated as the complete file URL.
func NewSource(client *http.Client, rawURL string, meta *metainfo.MetaInfo) (*Source, error) {
	if client == nil {
		return nil, classified(ClassPermanent, "create source", rawURL, 0, fmt.Errorf("nil HTTP client"))
	}
	if meta == nil {
		return nil, classified(ClassPermanent, "create source", rawURL, 0, fmt.Errorf("nil metainfo"))
	}
	layout, err := storage.NewLayout(meta)
	if err != nil {
		return nil, classified(ClassPermanent, "create source", rawURL, 0, err)
	}
	base, err := url.Parse(rawURL)
	if err != nil {
		return nil, classified(ClassPermanent, "parse URL", rawURL, 0, err)
	}
	scheme := strings.ToLower(base.Scheme)
	if scheme == "ftp" {
		return nil, classified(ClassPermanent, "create source", rawURL, 0, fmt.Errorf("FTP is not supported"))
	}
	if (scheme != "http" && scheme != "https") || base.Host == "" || base.Opaque != "" {
		return nil, classified(ClassPermanent, "create source", rawURL, 0, fmt.Errorf("URL must be absolute HTTP or HTTPS"))
	}
	if base.Fragment != "" {
		return nil, classified(ClassPermanent, "create source", rawURL, 0, fmt.Errorf("URL must not contain a fragment"))
	}
	base.Scheme = scheme

	singlePath, singleLength, singlePadding, single := singleFile(&meta.Info)
	baseURL := strings.HasSuffix(base.EscapedPath(), "/")
	if !single && !baseURL {
		return nil, classified(ClassPermanent, "create source", rawURL, 0, fmt.Errorf("multi-file URL must end in a slash"))
	}

	source := &Source{
		client: client,
		layout: layout,
		files:  make(map[string]remoteFile),
		url:    base.String(),
	}
	addFile := func(path []string, length int64, padding bool, endpoint string) error {
		if padding {
			return nil
		}
		key := filepath.Join(path...)
		file := remoteFile{url: endpoint, length: length}
		if previous, ok := source.files[key]; ok {
			if previous != file {
				return fmt.Errorf("file %q has conflicting web-seed mappings", key)
			}
			return nil
		}
		source.files[key] = file
		return nil
	}

	if single {
		endpoint := base.String()
		if baseURL {
			endpoint, err = appendURL(base, meta.Info.Name)
			if err != nil {
				return nil, classified(ClassPermanent, "resolve URL", rawURL, 0, err)
			}
		}
		if err := addFile(singlePath, singleLength, singlePadding, endpoint); err != nil {
			return nil, classified(ClassPermanent, "create source", rawURL, 0, err)
		}
	} else {
		add := func(file metainfo.FileInfo) error {
			components := make([]string, 1, len(file.Path)+1)
			components[0] = meta.Info.Name
			components = append(components, file.Path...)
			endpoint, err := appendURL(base, components...)
			if err != nil {
				return err
			}
			return addFile(file.Path, file.Length, file.IsPadding(), endpoint)
		}
		if meta.Info.HasV1() {
			for _, file := range meta.Info.Files {
				if err := add(file); err != nil {
					return nil, classified(ClassPermanent, "resolve URL", rawURL, 0, err)
				}
			}
		}
		if meta.Info.HasV2() {
			for _, file := range meta.Info.V2Files {
				if err := add(file); err != nil {
					return nil, classified(ClassPermanent, "resolve URL", rawURL, 0, err)
				}
			}
		}
	}

	source.checks, err = buildChecks(meta, layout)
	if err != nil {
		return nil, classified(ClassPermanent, "create source", rawURL, 0, err)
	}
	return source, nil
}

// Bad reports whether an integrity failure permanently disabled the source.
func (s *Source) Bad() bool { return s != nil && s.bad.Load() }

// ReadPiece reads one complete, unverified protocol piece. Padding bytes are
// zero-filled without making a remote request.
func (s *Source) ReadPiece(ctx context.Context, protocol storage.Protocol, index int) ([]byte, error) {
	if s == nil || s.layout == nil {
		return nil, classified(ClassPermanent, "read piece", "", 0, fmt.Errorf("nil source"))
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if s.bad.Load() {
		return nil, s.disabled("read piece")
	}
	length, err := s.layout.PieceLength(protocol, index)
	if err != nil {
		return nil, classified(ClassPermanent, "read piece", s.url, 0, err)
	}
	if length < 0 || uint64(length) > uint64(^uint(0)>>1) {
		return nil, classified(ClassPermanent, "read piece", s.url, 0, fmt.Errorf("piece length %d does not fit memory", length))
	}
	data := make([]byte, int(length))
	n, err := s.ReadAt(ctx, protocol, index, data, 0)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, classified(ClassTransient, "read piece", s.url, 0, fmt.Errorf("read %d bytes, want %d", n, len(data)))
	}
	return data, nil
}

// ReadAt fills p from begin bytes into a protocol piece. It follows file
// boundaries and returns the number of logical piece bytes filled.
func (s *Source) ReadAt(ctx context.Context, protocol storage.Protocol, index int, p []byte, begin int64) (int, error) {
	if s == nil || s.layout == nil {
		return 0, classified(ClassPermanent, "read range", "", 0, fmt.Errorf("nil source"))
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	if s.bad.Load() {
		return 0, s.disabled("read range")
	}
	spans, err := s.layout.Spans(protocol, index, begin, int64(len(p)))
	if err != nil {
		return 0, classified(ClassPermanent, "read range", s.url, 0, err)
	}
	clear(p)
	n := 0
	for _, span := range spans {
		start64 := span.PieceOffset - begin
		if start64 < 0 || start64 > int64(len(p)) || span.Length > int64(len(p))-start64 {
			return n, classified(ClassPermanent, "read range", s.url, 0, fmt.Errorf("invalid storage span for %q", span.Path))
		}
		start := int(start64)
		stop := start + int(span.Length)
		if span.Padding {
			n += stop - start
			continue
		}
		if s.bad.Load() {
			return n, s.disabled("read range")
		}
		file, ok := s.files[span.Path]
		if !ok {
			return n, classified(ClassPermanent, "read range", s.url, 0, fmt.Errorf("no URL for file %q", span.Path))
		}
		if err := s.readRemote(ctx, file, p[start:stop], span.FileOffset); err != nil {
			return n, err
		}
		n += stop - start
	}
	if n != len(p) {
		return n, classified(ClassPermanent, "read range", s.url, 0, fmt.Errorf("storage spans cover %d bytes, want %d", n, len(p)))
	}
	return n, nil
}

func (s *Source) readRemote(ctx context.Context, file remoteFile, p []byte, offset int64) error {
	length := int64(len(p))
	if length <= 0 || offset < 0 || offset > file.length || length > file.length-offset {
		return classified(ClassPermanent, "read range", file.url, 0, fmt.Errorf("range %d+%d is outside file length %d", offset, length, file.length))
	}
	end := offset + length - 1
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, file.url, http.NoBody)
	if err != nil {
		return classified(ClassPermanent, "create request", file.url, 0, err)
	}
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))
	request.Header.Set("Accept-Encoding", "identity")
	response, err := s.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		class, cause := transportError(ctx, err)
		return classified(class, "request", file.url, 0, cause)
	}

	if err := validateResponse(response, file, offset, end, length); err != nil {
		_ = response.Body.Close()
		return err
	}
	n, readErr := io.ReadFull(response.Body, p)
	if readErr != nil {
		_ = response.Body.Close()
		class, cause := transportError(ctx, readErr)
		return classified(class, "read response", file.url, response.StatusCode, fmt.Errorf("received %d of %d bytes: %w", n, len(p), cause))
	}
	var extra [1]byte
	extraBytes, extraErr := io.ReadFull(response.Body, extra[:])
	if extraBytes != 0 {
		_ = response.Body.Close()
		return classified(ClassPermanent, "read response", file.url, response.StatusCode, fmt.Errorf("response exceeds %d bytes", len(p)))
	}
	if extraErr != nil && !errors.Is(extraErr, io.EOF) {
		_ = response.Body.Close()
		class, cause := transportError(ctx, extraErr)
		return classified(class, "read response", file.url, response.StatusCode, cause)
	}
	if err := response.Body.Close(); err != nil {
		class, cause := transportError(ctx, err)
		return classified(class, "close response", file.url, response.StatusCode, cause)
	}
	return nil
}

func validateResponse(response *http.Response, file remoteFile, start, end, length int64) error {
	class := statusClass(response.StatusCode)
	switch response.StatusCode {
	case http.StatusPartialContent:
		values := response.Header.Values("Content-Range")
		if len(values) != 1 {
			return classified(ClassPermanent, "validate response", file.url, response.StatusCode, fmt.Errorf("expected one Content-Range header"))
		}
		gotStart, gotEnd, total, err := parseContentRange(values[0])
		if err != nil {
			return classified(ClassPermanent, "validate response", file.url, response.StatusCode, err)
		}
		if gotStart != start || gotEnd != end || total != file.length {
			return classified(ClassPermanent, "validate response", file.url, response.StatusCode, fmt.Errorf("Content-Range is bytes %d-%d/%d, want bytes %d-%d/%d", gotStart, gotEnd, total, start, end, file.length))
		}
	case http.StatusOK:
		if start != 0 || length != file.length {
			return classified(ClassPermanent, "validate response", file.url, response.StatusCode, fmt.Errorf("server ignored a partial Range request"))
		}
		if len(response.Header.Values("Content-Range")) != 0 {
			return classified(ClassPermanent, "validate response", file.url, response.StatusCode, fmt.Errorf("200 response contains Content-Range"))
		}
	default:
		return classified(class, "request", file.url, response.StatusCode, nil)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return classified(ClassPermanent, "validate response", file.url, response.StatusCode, fmt.Errorf("unsupported Content-Encoding %q", encoding))
	}
	if response.ContentLength >= 0 && response.ContentLength != length {
		return classified(ClassPermanent, "validate response", file.url, response.StatusCode, fmt.Errorf("Content-Length is %d, want %d", response.ContentLength, length))
	}
	return nil
}

func parseContentRange(value string) (int64, int64, int64, error) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	rangePart, totalPart, ok := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !ok {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	startPart, endPart, ok := strings.Cut(rangePart, "-")
	if !ok {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	start, err := decimal(startPart)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	end, err := decimal(endPart)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	total, err := decimal(totalPart)
	if err != nil || end < start || end >= total {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	return start, end, total, nil
}

func decimal(value string) (int64, error) {
	if value == "" {
		return 0, fmt.Errorf("empty decimal")
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("invalid decimal")
		}
	}
	return strconv.ParseInt(value, 10, 64)
}

func statusClass(status int) ErrorClass {
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		return ClassBusy
	}
	if status == http.StatusRequestTimeout || status == http.StatusTooEarly || status >= 500 && status <= 599 {
		return ClassTransient
	}
	return ClassPermanent
}

func transportError(ctx context.Context, err error) (ErrorClass, error) {
	if ctx != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return ClassCanceled, contextErr
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ClassCanceled, err
	}
	return ClassTransient, err
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return classified(ClassPermanent, "read", "", 0, fmt.Errorf("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return classified(ClassCanceled, "read", "", 0, err)
	}
	return nil
}

func classified(class ErrorClass, op, rawURL string, status int, err error) error {
	return &Error{Class: class, Op: op, URL: rawURL, StatusCode: status, Err: err}
}

func (s *Source) disabled(op string) error {
	return classified(ClassDisabled, op, s.url, 0, fmt.Errorf("source was disabled after an integrity failure"))
}

func singleFile(info *metainfo.Info) ([]string, int64, bool, bool) {
	if info.HasV1() && len(info.Files) == 0 {
		return []string{info.Name}, info.Length, strings.Contains(info.Attr, "p"), true
	}
	if !info.HasV1() && len(info.V2Files) == 1 && samePath(info.V2Files[0].Path, []string{info.Name}) {
		file := info.V2Files[0]
		return file.Path, file.Length, file.IsPadding(), true
	}
	return nil, 0, false, false
}

func samePath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func appendURL(base *url.URL, components ...string) (string, error) {
	escapedPath := base.EscapedPath()
	if !strings.HasSuffix(escapedPath, "/") {
		escapedPath += "/"
	}
	for i, component := range components {
		if i != 0 {
			escapedPath += "/"
		}
		escapedPath += url.PathEscape(component)
	}
	path, err := url.PathUnescape(escapedPath)
	if err != nil {
		return "", err
	}
	resolved := *base
	resolved.Path = path
	resolved.RawPath = escapedPath
	return resolved.String(), nil
}

func buildChecks(meta *metainfo.MetaInfo, layout *storage.Layout) (map[storage.Protocol][]pieceCheck, error) {
	checks := make(map[storage.Protocol][]pieceCheck, 2)
	if meta.Info.HasV1() {
		v1 := make([]pieceCheck, len(meta.Info.Pieces))
		for i, hash := range meta.Info.Pieces {
			v1[i].v1 = hash
		}
		checks[storage.V1] = v1
	}
	if meta.Info.HasV2() {
		var v2 []pieceCheck
		for _, file := range meta.Info.V2Files {
			if file.Length == 0 {
				continue
			}
			if file.PiecesRoot == nil {
				return nil, fmt.Errorf("v2 file %q has no pieces root", strings.Join(file.Path, "/"))
			}
			count := 1 + (file.Length-1)/meta.Info.PieceLength
			var layer []metainfo.HashV2
			if count > 1 {
				var ok bool
				layer, ok = meta.PieceLayers[*file.PiecesRoot]
				if !ok || int64(len(layer)) != count {
					return nil, fmt.Errorf("v2 file %q has no complete piece layer", strings.Join(file.Path, "/"))
				}
			}
			span := v2PieceSpan(file.Length, meta.Info.PieceLength)
			for local := int64(0); local < count; local++ {
				hash := *file.PiecesRoot
				if layer != nil {
					hash = layer[int(local)]
				}
				v2 = append(v2, pieceCheck{v2: hash, v2Span: span})
			}
		}
		count, err := layout.PieceCount(storage.V2)
		if err != nil {
			return nil, err
		}
		if len(v2) != count {
			return nil, fmt.Errorf("built %d v2 checks, want %d", len(v2), count)
		}
		checks[storage.V2] = v2
	}
	return checks, nil
}

func v2PieceSpan(fileLength, pieceLength int64) int64 {
	if fileLength > pieceLength {
		return pieceLength
	}
	blocks := 1 + (fileLength-1)/v2BlockLength
	leaves := int64(1)
	for leaves < blocks {
		leaves *= 2
	}
	return leaves * v2BlockLength
}

// Downloader reads and verifies complete pieces from one Source.
type Downloader struct {
	source *Source
}

// NewDownloader returns a verifier for source.
func NewDownloader(source *Source) (*Downloader, error) {
	if source == nil {
		return nil, classified(ClassPermanent, "create downloader", "", 0, fmt.Errorf("nil source"))
	}
	return &Downloader{source: source}, nil
}

// ReadPiece downloads a piece and verifies every v1 and v2 hash available for
// its index. For hybrid padding, v1's trailing zero bytes are added or removed
// locally when checking the other protocol view. A mismatch permanently
// disables the Source before the error is returned.
func (d *Downloader) ReadPiece(ctx context.Context, protocol storage.Protocol, index int) ([]byte, error) {
	if d == nil || d.source == nil {
		return nil, classified(ClassPermanent, "download piece", "", 0, fmt.Errorf("nil downloader"))
	}
	data, err := d.source.ReadPiece(ctx, protocol, index)
	if err != nil {
		return nil, err
	}
	if checks, ok := d.source.checks[storage.V1]; ok {
		if index < 0 || index >= len(checks) {
			return nil, classified(ClassPermanent, "verify piece", d.source.url, 0, fmt.Errorf("v1 piece index %d has no hash", index))
		}
		length, err := d.source.layout.PieceLength(storage.V1, index)
		if err != nil {
			return nil, classified(ClassPermanent, "verify piece", d.source.url, 0, err)
		}
		got, err := v1Root(data, length)
		if err != nil {
			return nil, classified(ClassPermanent, "verify piece", d.source.url, 0, err)
		}
		if got != checks[index].v1 {
			return nil, d.mismatch(storage.V1, index, got.String(), checks[index].v1.String())
		}
	}
	if checks, ok := d.source.checks[storage.V2]; ok {
		if index < 0 || index >= len(checks) {
			return nil, classified(ClassPermanent, "verify piece", d.source.url, 0, fmt.Errorf("v2 piece index %d has no hash", index))
		}
		length, err := d.source.layout.PieceLength(storage.V2, index)
		if err != nil {
			return nil, classified(ClassPermanent, "verify piece", d.source.url, 0, err)
		}
		if length < 0 || uint64(length) > uint64(len(data)) {
			return nil, classified(ClassPermanent, "verify piece", d.source.url, 0, fmt.Errorf("v2 piece length %d exceeds downloaded length %d", length, len(data)))
		}
		got, err := v2Root(data[:int(length)], checks[index].v2Span)
		if err != nil {
			return nil, classified(ClassPermanent, "verify piece", d.source.url, 0, err)
		}
		if got != checks[index].v2 {
			return nil, d.mismatch(storage.V2, index, got.String(), checks[index].v2.String())
		}
	}
	if d.source.bad.Load() {
		return nil, d.source.disabled("verify piece")
	}
	return data, nil
}

func (d *Downloader) mismatch(protocol storage.Protocol, index int, got, want string) error {
	d.source.bad.Store(true)
	return classified(ClassIntegrity, "verify piece", d.source.url, 0, fmt.Errorf("%s piece %d hash mismatch: got %s, want %s", protocol, index, got, want))
}

func v1Root(data []byte, length int64) (metainfo.Hash, error) {
	if length < int64(len(data)) {
		return metainfo.Hash{}, fmt.Errorf("downloaded length %d exceeds v1 piece length %d", len(data), length)
	}
	hash := sha1.New()
	_, _ = hash.Write(data)
	var zeros [32 << 10]byte
	for remaining := length - int64(len(data)); remaining > 0; {
		chunk := min(remaining, int64(len(zeros)))
		_, _ = hash.Write(zeros[:int(chunk)])
		remaining -= chunk
	}
	var root metainfo.Hash
	copy(root[:], hash.Sum(nil))
	return root, nil
}

func v2Root(data []byte, span int64) (metainfo.HashV2, error) {
	if len(data) == 0 || span < v2BlockLength || span&(span-1) != 0 || int64(len(data)) > span {
		return metainfo.HashV2{}, fmt.Errorf("%d bytes do not fit v2 span %d", len(data), span)
	}
	leaves64 := span / v2BlockLength
	if uint64(leaves64) > uint64(^uint(0)>>1) {
		return metainfo.HashV2{}, fmt.Errorf("v2 span %d has too many leaves", span)
	}
	leaves := int(leaves64)
	hashes := make([]metainfo.HashV2, leaves)
	for begin := 0; begin < len(data); begin += int(v2BlockLength) {
		end := min(begin+int(v2BlockLength), len(data))
		hashes[begin/int(v2BlockLength)] = sha256.Sum256(data[begin:end])
	}
	for width := len(hashes); width > 1; width /= 2 {
		for i := 0; i < width; i += 2 {
			var pair [sha256.Size * 2]byte
			copy(pair[:sha256.Size], hashes[i][:])
			copy(pair[sha256.Size:], hashes[i+1][:])
			hashes[i/2] = sha256.Sum256(pair[:])
		}
	}
	return hashes[0], nil
}
