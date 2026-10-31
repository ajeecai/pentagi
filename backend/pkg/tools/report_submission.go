package tools

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"pentagi/pkg/database"

	"github.com/containerd/errdefs"
)

const SubmitReportToolName = "submit_report"
const SubmittedReportPrefix = "submitted_report:"
const maxSubmittedReportSize = 1024 * 1024

type SubmitReportAction struct {
	Path    string `json:"path" jsonschema:"required" jsonschema_description:"Absolute path of the final Markdown security report. Submitting confirms that the assessment is complete and closes the entire current task, including remaining planned subtasks. The report must contain the sdp-vulnerability-summary JSON block."`
	Message string `json:"message" jsonschema:"required" jsonschema_description:"Brief completion confirmation; do not copy the report body."`
}

type SubmittedReport struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Content string `json:"-"`
}

// SubmittedReportForTask reads the immutable delivery receipt, not an agent's completion claim.
func SubmittedReportForTask(ctx context.Context, db database.Querier, flowID, taskID int64) (*SubmittedReport, error) {
	logs, err := db.GetTaskMsgLogs(ctx, database.Int64ToNullInt64(&taskID))
	if err != nil {
		return nil, err
	}
	for _, log := range logs {
		if log.FlowID != flowID || !log.TaskID.Valid || log.TaskID.Int64 != taskID || log.Type != database.MsglogTypeReport || !strings.HasPrefix(log.Message, SubmittedReportPrefix) {
			continue
		}
		var receipt SubmittedReport
		if err := json.Unmarshal([]byte(strings.TrimPrefix(log.Message, SubmittedReportPrefix)), &receipt); err != nil {
			return nil, fmt.Errorf("invalid report receipt: %w", err)
		}
		if receipt.Path == "" || receipt.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(log.Result))) {
			return nil, errors.New("submitted report checksum mismatch")
		}
		receipt.Content = log.Result
		return &receipt, nil
	}
	return nil, nil
}

func validateSubmittedReport(content string) error {
	if len(content) > maxSubmittedReportSize || !utf8.ValidString(content) || strings.TrimSpace(content) == "" {
		return errors.New("report must be nonempty UTF-8 text of at most 1 MiB")
	}
	const marker = "```sdp-vulnerability-summary"
	if strings.Count(content, marker) != 1 {
		return errors.New("report must contain exactly one fenced sdp-vulnerability-summary JSON block")
	}
	_, tail, _ := strings.Cut(content, marker)
	if !strings.HasPrefix(tail, "\n") && !strings.HasPrefix(tail, "\r\n") {
		return errors.New("summary JSON must start on the line after the fence")
	}
	raw, _, closed := strings.Cut(tail, "```")
	if !closed || len(raw) > 2048 {
		return errors.New("summary JSON fence is missing or the block exceeds 2048 bytes")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return fmt.Errorf("invalid summary JSON: %w", err)
	}
	for _, key := range []string{"version", "critical", "high", "medium", "low", "informational"} {
		value, ok := fields[key]
		var count int64
		if !ok || string(value) == "null" || json.Unmarshal(value, &count) != nil || count < 0 || count > 1000000 {
			return fmt.Errorf("summary.%s must be a top-level integer between 0 and 1000000", key)
		}
		if key == "version" && count != 1 {
			return errors.New("summary.version must equal 1")
		}
	}
	return nil
}

// submitReport snapshots the file before accepting delivery; retries reuse that snapshot even after container removal.
func (fte *flowToolsExecutor) submitReport(ctx context.Context, taskID, subtaskID int64, args json.RawMessage) (*SubmittedReport, error) {
	var action SubmitReportAction
	if err := json.Unmarshal(args, &action); err != nil {
		return nil, reportValidationError{err}
	}
	if !path.IsAbs(action.Path) || path.Clean(action.Path) != action.Path || path.Ext(action.Path) != ".md" {
		return nil, reportValidationError{errors.New("path must be a clean absolute Markdown file path")}
	}
	previous, err := SubmittedReportForTask(ctx, fte.db, fte.flowID, taskID)
	if err != nil {
		return nil, err
	}
	if previous != nil {
		if previous.Path != action.Path {
			return nil, reportValidationError{errors.New("this task already submitted a different report; its accepted report is immutable")}
		}
		return previous, nil
	}
	reader, stat, err := fte.docker.CopyFromContainer(ctx, PrimaryTerminalName(fte.cfg.TenantPrefix(), fte.flowID), action.Path)
	if errdefs.IsNotFound(err) {
		return nil, reportValidationError{errors.New("report file or its container is missing; ensure the report is written in the primary tool container before submitting")}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read report: %w", err)
	}
	defer reader.Close()
	if !stat.Mode.IsRegular() {
		return nil, reportValidationError{errors.New("report must be a regular file, not a directory or symlink")}
	}
	archive := tar.NewReader(reader)
	header, err := archive.Next()
	if err != nil {
		return nil, fmt.Errorf("cannot read report archive: %w", err)
	}
	if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size <= 0 || header.Size > maxSubmittedReportSize {
		return nil, reportValidationError{errors.New("report must be a nonempty regular file of at most 1 MiB")}
	}
	body, err := io.ReadAll(io.LimitReader(archive, maxSubmittedReportSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != header.Size {
		return nil, errors.New("incomplete report archive")
	}
	if _, err := archive.Next(); err != io.EOF {
		return nil, errors.New("report archive must contain exactly one file")
	}
	if err := validateSubmittedReport(string(body)); err != nil {
		return nil, reportValidationError{err}
	}
	receipt := &SubmittedReport{Path: action.Path, SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), Content: string(body)}
	metadata, _ := json.Marshal(receipt)
	_, err = fte.db.CreateResultMsgLog(ctx, database.CreateResultMsgLogParams{
		Type: database.MsglogTypeReport, Message: SubmittedReportPrefix + string(metadata), Result: receipt.Content,
		ResultFormat: database.MsglogResultFormatMarkdown, FlowID: fte.flowID,
		TaskID: database.Int64ToNullInt64(&taskID), SubtaskID: database.Int64ToNullInt64(&subtaskID),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot save submitted report: %w", err)
	}
	return receipt, nil
}

type reportValidationError struct{ error }
