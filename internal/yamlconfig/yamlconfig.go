// Package yamlconfig performs path-addressed, node-aware YAML edits.
package yamlconfig

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nfraynor/agent-smith/internal/filesystem"
	"gopkg.in/yaml.v3"
)

var (
	ErrPathNotFound = errors.New("YAML path not found")
	ErrInvalidPath  = errors.New("invalid YAML path")
)

type Service struct {
	files    *filesystem.Service
	maxBytes int64
}

type Preview struct {
	Path    string `json:"path"`
	Before  any    `json:"before,omitempty"`
	After   any    `json:"after,omitempty"`
	Diff    string `json:"diff"`
	Content []byte `json:"-"`
}

func New(files *filesystem.Service, maxBytes int64) *Service {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	return &Service{files: files, maxBytes: maxBytes}
}

func (s *Service) Get(root, file, path string) (any, error) {
	doc, _, err := s.load(root, file)
	if err != nil {
		return nil, err
	}
	node, _, _, err := find(doc, path)
	if err != nil {
		return nil, err
	}
	return decode(node)
}

func (s *Service) PreviewSet(root, file, path string, value any) (Preview, error) {
	return s.preview(root, file, path, value, false)
}

func (s *Service) PreviewDelete(root, file, path string) (Preview, error) {
	return s.preview(root, file, path, nil, true)
}

func (s *Service) Set(root, file, path string, value any) (Preview, error) {
	preview, err := s.PreviewSet(root, file, path, value)
	if err != nil {
		return Preview{}, err
	}
	if err = s.files.WriteAtomic(root, file, preview.Content, 0); err != nil {
		return Preview{}, err
	}
	return preview, nil
}

func (s *Service) Delete(root, file, path string) (Preview, error) {
	preview, err := s.PreviewDelete(root, file, path)
	if err != nil {
		return Preview{}, err
	}
	if err = s.files.WriteAtomic(root, file, preview.Content, 0); err != nil {
		return Preview{}, err
	}
	return preview, nil
}

func (s *Service) preview(root, file, path string, value any, deleting bool) (Preview, error) {
	doc, original, err := s.load(root, file)
	if err != nil {
		return Preview{}, err
	}
	node, parent, index, err := find(doc, path)
	if err != nil {
		return Preview{}, err
	}
	before, err := decode(node)
	if err != nil {
		return Preview{}, err
	}
	result := Preview{Path: path, Before: before}
	if deleting {
		if parent == nil || parent.Kind == yaml.DocumentNode {
			return Preview{}, fmt.Errorf("%w: cannot delete document root", ErrInvalidPath)
		}
		if parent.Kind == yaml.MappingNode {
			parent.Content = append(parent.Content[:index-1], parent.Content[index+1:]...)
		} else {
			parent.Content = append(parent.Content[:index], parent.Content[index+1:]...)
		}
	} else {
		replacement, err := encode(value)
		if err != nil {
			return Preview{}, err
		}
		// Preserve comments anchored on the value being replaced.
		replacement.HeadComment = node.HeadComment
		replacement.LineComment = node.LineComment
		replacement.FootComment = node.FootComment
		if parent == nil {
			doc.Content[0] = replacement
		} else {
			parent.Content[index] = replacement
		}
		result.After = value
	}
	content, err := yaml.Marshal(doc)
	if err != nil {
		return Preview{}, fmt.Errorf("marshal YAML: %w", err)
	}
	// Validate the exact bytes that will be written.
	var validation yaml.Node
	if err = yaml.Unmarshal(content, &validation); err != nil {
		return Preview{}, fmt.Errorf("validate YAML: %w", err)
	}
	result.Content = content
	result.Diff = filesystem.UnifiedDiff(original, content, "current/"+file, "proposed/"+file)
	return result, nil
}

func (s *Service) load(root, file string) (*yaml.Node, []byte, error) {
	read, err := s.files.Read(root, file, 0, s.maxBytes)
	if err != nil {
		return nil, nil, err
	}
	if read.Truncated {
		return nil, nil, filesystem.ErrLimitExceeded
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(read.Data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		return nil, nil, errors.New("empty YAML document")
	}
	return &doc, read.Data, nil
}

type segment struct {
	key   *string
	index *int
}

func parsePath(path string) ([]segment, error) {
	if path == "" {
		return nil, nil
	}
	if strings.HasPrefix(path, ".") || strings.HasSuffix(path, ".") {
		return nil, ErrInvalidPath
	}
	var out []segment
	var key strings.Builder
	flush := func() error {
		if key.Len() == 0 {
			return ErrInvalidPath
		}
		k := key.String()
		key.Reset()
		out = append(out, segment{key: &k})
		return nil
	}
	escaped := false
	for i := 0; i < len(path); i++ {
		c := path[i]
		if escaped {
			key.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		switch c {
		case '.':
			if err := flush(); err != nil {
				return nil, err
			}
		case '[':
			if key.Len() > 0 {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			end := strings.IndexByte(path[i:], ']')
			if end < 2 {
				return nil, ErrInvalidPath
			}
			end += i
			n, err := strconv.Atoi(path[i+1 : end])
			if err != nil || n < 0 {
				return nil, ErrInvalidPath
			}
			out = append(out, segment{index: &n})
			i = end
			if i+1 < len(path) && path[i+1] != '.' && path[i+1] != '[' {
				return nil, ErrInvalidPath
			}
			if i+1 < len(path) && path[i+1] == '.' {
				i++
			}
		default:
			key.WriteByte(c)
		}
	}
	if escaped {
		return nil, ErrInvalidPath
	}
	if key.Len() > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, ErrInvalidPath
	}
	return out, nil
}

func find(doc *yaml.Node, path string) (node, parent *yaml.Node, index int, err error) {
	segments, err := parsePath(path)
	if err != nil {
		return nil, nil, 0, err
	}
	node = doc
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) != 1 {
			return nil, nil, 0, ErrPathNotFound
		}
		parent = node
		index = 0
		node = node.Content[0]
	}
	for _, seg := range segments {
		if node.Kind == yaml.AliasNode {
			node = node.Alias
		}
		parent = node
		if seg.key != nil {
			if node.Kind != yaml.MappingNode {
				return nil, nil, 0, ErrPathNotFound
			}
			found := false
			for i := 0; i+1 < len(node.Content); i += 2 {
				if node.Content[i].Value == *seg.key {
					index = i + 1
					node = node.Content[index]
					found = true
					break
				}
			}
			if !found {
				return nil, nil, 0, fmt.Errorf("%w: %s", ErrPathNotFound, *seg.key)
			}
		} else {
			if node.Kind != yaml.SequenceNode || *seg.index >= len(node.Content) {
				return nil, nil, 0, ErrPathNotFound
			}
			index = *seg.index
			node = node.Content[index]
		}
	}
	return node, parent, index, nil
}

func decode(node *yaml.Node) (any, error) {
	var value any
	if err := node.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func encode(value any) (*yaml.Node, error) {
	var wrapper yaml.Node
	if err := wrapper.Encode(value); err != nil {
		return nil, fmt.Errorf("encode YAML value: %w", err)
	}
	if wrapper.Kind == yaml.DocumentNode && len(wrapper.Content) == 1 {
		return wrapper.Content[0], nil
	}
	return &wrapper, nil
}
