// Package docker provides bounded, structured access to the Docker Engine.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	containertypes "github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"
)

const defaultMaxLogBytes int64 = 1 << 20

var ErrInvalidArgument = errors.New("invalid docker argument")

// Engine is the subset of the Docker SDK used by Service. It is intentionally
// small so callers can unit test operational workflows without a Docker daemon.
type Engine interface {
	ContainerList(context.Context, mobyclient.ContainerListOptions) (mobyclient.ContainerListResult, error)
	ContainerInspect(context.Context, string, mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error)
	ContainerLogs(context.Context, string, mobyclient.ContainerLogsOptions) (mobyclient.ContainerLogsResult, error)
	ContainerStats(context.Context, string, mobyclient.ContainerStatsOptions) (mobyclient.ContainerStatsResult, error)
	ContainerRestart(context.Context, string, mobyclient.ContainerRestartOptions) (mobyclient.ContainerRestartResult, error)
	ContainerStart(context.Context, string, mobyclient.ContainerStartOptions) (mobyclient.ContainerStartResult, error)
	ContainerStop(context.Context, string, mobyclient.ContainerStopOptions) (mobyclient.ContainerStopResult, error)
	ImagePull(context.Context, string, mobyclient.ImagePullOptions) (mobyclient.ImagePullResponse, error)
	ImageInspect(context.Context, string, ...mobyclient.ImageInspectOption) (mobyclient.ImageInspectResult, error)
}

type Service struct {
	engine      Engine
	maxLogBytes int64
}

func New(engine Engine, maxLogBytes int64) *Service {
	if maxLogBytes <= 0 {
		maxLogBytes = defaultMaxLogBytes
	}
	return &Service{engine: engine, maxLogBytes: maxLogBytes}
}

type Port struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort uint16 `json:"privatePort"`
	PublicPort  uint16 `json:"publicPort,omitempty"`
	Type        string `json:"type"`
}

type Container struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Image        string    `json:"image"`
	ImageID      string    `json:"imageId,omitempty"`
	State        string    `json:"state"`
	Status       string    `json:"status"`
	Health       string    `json:"health,omitempty"`
	Ports        []Port    `json:"ports,omitempty"`
	StartedAt    time.Time `json:"startedAt,omitempty"`
	RestartCount int       `json:"restartCount"`
}

type InspectResult struct {
	Container
	Created     time.Time         `json:"created,omitempty"`
	Platform    string            `json:"platform,omitempty"`
	Entrypoint  []string          `json:"entrypoint,omitempty"`
	Command     []string          `json:"command,omitempty"`
	Environment []string          `json:"environment,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
}

type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"readOnly"`
}

type LogsResult struct {
	Container string `json:"container"`
	Lines     int    `json:"lines"`
	Truncated bool   `json:"truncated"`
	Content   string `json:"content"`
}

type Stats struct {
	Container   string  `json:"container"`
	CPUPercent  float64 `json:"cpuPercent"`
	MemoryBytes uint64  `json:"memoryBytes"`
	MemoryLimit uint64  `json:"memoryLimit"`
	NetworkRx   uint64  `json:"networkRxBytes"`
	NetworkTx   uint64  `json:"networkTxBytes"`
	BlockRead   uint64  `json:"blockReadBytes"`
	BlockWrite  uint64  `json:"blockWriteBytes"`
	PIDs        uint64  `json:"pids"`
}

type ActionResult struct {
	Container string    `json:"container"`
	Before    Container `json:"before"`
	After     Container `json:"after"`
}

type PullResult struct {
	Image          string `json:"image"`
	PreviousID     string `json:"previousId,omitempty"`
	CurrentID      string `json:"currentId"`
	PreviousDigest string `json:"previousDigest,omitempty"`
	CurrentDigest  string `json:"currentDigest,omitempty"`
}

type ImageInfo struct {
	Image       string    `json:"image"`
	ID          string    `json:"id"`
	RepoTags    []string  `json:"repoTags,omitempty"`
	RepoDigests []string  `json:"repoDigests,omitempty"`
	Created     time.Time `json:"created,omitempty"`
	Size        int64     `json:"size"`
}

func (s *Service) List(ctx context.Context, all bool) ([]Container, error) {
	response, err := s.engine.ContainerList(ctx, mobyclient.ContainerListOptions{All: all})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	result := make([]Container, 0, len(response.Items))
	for _, item := range response.Items {
		c := Container{ID: item.ID, Image: item.Image, ImageID: item.ImageID, State: string(item.State), Status: item.Status}
		if len(item.Names) > 0 {
			c.Name = strings.TrimPrefix(item.Names[0], "/")
		}
		for _, p := range item.Ports {
			c.Ports = append(c.Ports, Port{IP: p.IP.String(), PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Type: p.Type})
		}
		if inspected, inspectErr := s.engine.ContainerInspect(ctx, item.ID, mobyclient.ContainerInspectOptions{}); inspectErr == nil {
			enrich(&c, inspected.Container)
		}
		result = append(result, c)
	}
	return result, nil
}

func (s *Service) Inspect(ctx context.Context, container string) (InspectResult, error) {
	if err := validValue("container", container); err != nil {
		return InspectResult{}, err
	}
	inspected, err := s.engine.ContainerInspect(ctx, container, mobyclient.ContainerInspectOptions{})
	if err != nil {
		return InspectResult{}, fmt.Errorf("inspect container %q: %w", container, err)
	}
	v := inspected.Container
	c := Container{ID: v.ID, Name: strings.TrimPrefix(v.Name, "/")}
	enrich(&c, v)
	r := InspectResult{Container: c, Platform: v.Platform}
	if v.Created != "" {
		r.Created, _ = time.Parse(time.RFC3339Nano, v.Created)
	}
	if v.Config != nil {
		r.Labels = cloneMap(v.Config.Labels)
		r.Environment = redactEnvironment(v.Config.Env)
		r.Entrypoint = append([]string(nil), v.Config.Entrypoint...)
		r.Command = append([]string(nil), v.Config.Cmd...)
	}
	for _, m := range v.Mounts {
		r.Mounts = append(r.Mounts, Mount{Type: string(m.Type), Source: m.Source, Destination: m.Destination, ReadOnly: !m.RW})
	}
	return r, nil
}

func (s *Service) Logs(ctx context.Context, container string, lines int, since string, timestamps bool) (LogsResult, error) {
	if err := validValue("container", container); err != nil {
		return LogsResult{}, err
	}
	if lines <= 0 {
		lines = 200
	}
	if lines > 10000 {
		lines = 10000
	}
	if strings.ContainsAny(since, "\x00\r\n") {
		return LogsResult{}, fmt.Errorf("%w: since", ErrInvalidArgument)
	}
	r, err := s.engine.ContainerLogs(ctx, container, mobyclient.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: fmt.Sprint(lines), Since: since, Timestamps: timestamps})
	if err != nil {
		return LogsResult{}, fmt.Errorf("read logs for %q: %w", container, err)
	}
	defer r.Close()
	limited := &limitBuffer{limit: s.maxLogBytes}
	if _, err = stdcopy.StdCopy(limited, limited, r); err != nil {
		// TTY streams are not multiplexed. Preserve their content instead.
		limited = &limitBuffer{limit: s.maxLogBytes}
		if _, seekErr := io.Copy(limited, r); seekErr != nil {
			return LogsResult{}, fmt.Errorf("decode logs for %q: %w", container, err)
		}
	}
	return LogsResult{Container: container, Lines: lines, Truncated: limited.truncated, Content: limited.String()}, nil
}

func (s *Service) Stats(ctx context.Context, container string) (Stats, error) {
	if err := validValue("container", container); err != nil {
		return Stats{}, err
	}
	r, err := s.engine.ContainerStats(ctx, container, mobyclient.ContainerStatsOptions{IncludePreviousSample: true})
	if err != nil {
		return Stats{}, fmt.Errorf("read stats for %q: %w", container, err)
	}
	defer r.Body.Close()
	var raw containertypes.StatsResponse
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&raw); err != nil {
		return Stats{}, fmt.Errorf("decode stats for %q: %w", container, err)
	}
	st := Stats{Container: container, MemoryBytes: raw.MemoryStats.Usage, MemoryLimit: raw.MemoryStats.Limit, PIDs: raw.PidsStats.Current}
	var cpuDelta, systemDelta float64
	if raw.CPUStats.CPUUsage.TotalUsage >= raw.PreCPUStats.CPUUsage.TotalUsage {
		cpuDelta = float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
	}
	if raw.CPUStats.SystemUsage >= raw.PreCPUStats.SystemUsage {
		systemDelta = float64(raw.CPUStats.SystemUsage - raw.PreCPUStats.SystemUsage)
	}
	cores := len(raw.CPUStats.CPUUsage.PercpuUsage)
	if cores == 0 {
		cores = int(raw.CPUStats.OnlineCPUs)
	}
	if systemDelta > 0 && cpuDelta >= 0 && cores > 0 {
		st.CPUPercent = cpuDelta / systemDelta * float64(cores) * 100
	}
	for _, n := range raw.Networks {
		st.NetworkRx += n.RxBytes
		st.NetworkTx += n.TxBytes
	}
	for _, e := range raw.BlkioStats.IoServiceBytesRecursive {
		if strings.EqualFold(e.Op, "read") {
			st.BlockRead += e.Value
		}
		if strings.EqualFold(e.Op, "write") {
			st.BlockWrite += e.Value
		}
	}
	return st, nil
}

func (s *Service) Restart(ctx context.Context, container string, timeout time.Duration) (ActionResult, error) {
	return s.mutate(ctx, container, func() error {
		secs := seconds(timeout)
		_, err := s.engine.ContainerRestart(ctx, container, mobyclient.ContainerRestartOptions{Timeout: secs})
		return err
	})
}

func (s *Service) Start(ctx context.Context, container string) (ActionResult, error) {
	return s.mutate(ctx, container, func() error {
		_, err := s.engine.ContainerStart(ctx, container, mobyclient.ContainerStartOptions{})
		return err
	})
}

func (s *Service) Stop(ctx context.Context, container string, timeout time.Duration) (ActionResult, error) {
	return s.mutate(ctx, container, func() error {
		secs := seconds(timeout)
		_, err := s.engine.ContainerStop(ctx, container, mobyclient.ContainerStopOptions{Timeout: secs})
		return err
	})
}

func (s *Service) Pull(ctx context.Context, image string) (PullResult, error) {
	if err := validValue("image", image); err != nil {
		return PullResult{}, err
	}
	before, _ := s.engine.ImageInspect(ctx, image)
	r, err := s.engine.ImagePull(ctx, image, mobyclient.ImagePullOptions{})
	if err != nil {
		return PullResult{}, fmt.Errorf("pull image %q: %w", image, err)
	}
	defer r.Close()
	if err := r.Wait(ctx); err != nil {
		return PullResult{}, fmt.Errorf("pull image %q: %w", image, err)
	}
	after, err := s.engine.ImageInspect(ctx, image)
	if err != nil {
		return PullResult{}, fmt.Errorf("inspect pulled image %q: %w", image, err)
	}
	return PullResult{Image: image, PreviousID: before.ID, CurrentID: after.ID, PreviousDigest: first(before.RepoDigests), CurrentDigest: first(after.RepoDigests)}, nil
}

func (s *Service) ImageInfo(ctx context.Context, image string) (ImageInfo, error) {
	if err := validValue("image", image); err != nil {
		return ImageInfo{}, err
	}
	v, err := s.engine.ImageInspect(ctx, image)
	if err != nil {
		return ImageInfo{}, fmt.Errorf("inspect image %q: %w", image, err)
	}
	r := ImageInfo{Image: image, ID: v.ID, RepoTags: append([]string(nil), v.RepoTags...), RepoDigests: append([]string(nil), v.RepoDigests...), Size: v.Size}
	if v.Created != "" {
		r.Created, _ = time.Parse(time.RFC3339Nano, v.Created)
	}
	return r, nil
}

func (s *Service) mutate(ctx context.Context, name string, action func() error) (ActionResult, error) {
	if err := validValue("container", name); err != nil {
		return ActionResult{}, err
	}
	before, err := s.Inspect(ctx, name)
	if err != nil {
		return ActionResult{}, err
	}
	if err := action(); err != nil {
		return ActionResult{}, fmt.Errorf("mutate container %q: %w", name, err)
	}
	after, err := s.Inspect(ctx, name)
	if err != nil {
		return ActionResult{}, fmt.Errorf("verify container %q: %w", name, err)
	}
	return ActionResult{Container: name, Before: before.Container, After: after.Container}, nil
}

func enrich(c *Container, v containertypes.InspectResponse) {
	if c.ID == "" {
		c.ID = v.ID
	}
	if c.Name == "" {
		c.Name = strings.TrimPrefix(v.Name, "/")
	}
	if v.Config != nil {
		if c.Image == "" {
			c.Image = v.Config.Image
		}
	}
	if v.State != nil {
		c.State = string(v.State.Status)
		c.Status = string(v.State.Status)
		c.RestartCount = v.RestartCount
		if v.State.Health != nil {
			c.Health = string(v.State.Health.Status)
		}
		c.StartedAt, _ = time.Parse(time.RFC3339Nano, v.State.StartedAt)
	}
}

func validValue(kind, value string) error {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%w: %s", ErrInvalidArgument, kind)
	}
	return nil
}
func seconds(d time.Duration) *int {
	if d <= 0 {
		return nil
	}
	n := int(d.Round(time.Second) / time.Second)
	if n < 1 {
		n = 1
	}
	return &n
}
func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func redactEnvironment(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		key, _, found := strings.Cut(value, "=")
		upper := strings.ToUpper(key)
		if found && (strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "API_KEY")) {
			result = append(result, key+"=[REDACTED]")
			continue
		}
		result = append(result, value)
	}
	return result
}

type limitBuffer struct {
	bytes.Buffer
	limit     int64
	truncated bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	original := len(p)
	left := b.limit - int64(b.Len())
	if left <= 0 {
		b.truncated = b.truncated || original > 0
		return original, nil
	}
	if int64(len(p)) > left {
		p = p[:left]
		b.truncated = true
	}
	_, _ = b.Buffer.Write(p)
	return original, nil
}
