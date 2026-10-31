package tools

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"pentagi/pkg/config"
	"pentagi/pkg/database"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/require"
)

const validSubmission = "# Report\nObserved service.\n```sdp-vulnerability-summary\n{\"version\":1,\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"informational\":1}\n```"

type submissionDB struct {
	database.Querier
	logs []database.Msglog
	fail error
}

func (d *submissionDB) GetTaskMsgLogs(context.Context, sql.NullInt64) ([]database.Msglog, error) {
	return d.logs, d.fail
}
func (d *submissionDB) CreateResultMsgLog(_ context.Context, p database.CreateResultMsgLogParams) (database.Msglog, error) {
	if d.fail != nil {
		return database.Msglog{}, d.fail
	}
	row := database.Msglog{Type: p.Type, Message: p.Message, Result: p.Result, FlowID: p.FlowID, TaskID: p.TaskID, SubtaskID: p.SubtaskID}
	d.logs = append(d.logs, row)
	return row, nil
}
func TestSubmitReportRejectsInvalidSummary(t *testing.T) {
	for _, content := range []string{"", "# Draft", strings.Replace(validSubmission, `"version":1`, `"version":2`, 1), strings.Replace(validSubmission, `"critical":0`, `"critical":null`, 1), strings.Replace(validSubmission, `"high":0`, `"high":-1`, 1), strings.Replace(validSubmission, `"low":0`, `"low":1.5`, 1), validSubmission + validSubmission} {
		require.Error(t, validateSubmittedReport(content))
	}
	require.NoError(t, validateSubmittedReport(validSubmission))
	require.NoError(t, validateSubmittedReport(validSubmission+strings.Repeat("\nEvidence", 5000)))
}
func TestSubmitReportSnapshotsAndReplaysWithoutContainer(t *testing.T) {
	db := &submissionDB{}
	docker := &fakeDockerClient{readFileContent: validSubmission}
	fte := &flowToolsExecutor{db: db, docker: docker, flowID: 7, cfg: &config.Config{}}
	args := json.RawMessage(`{"path":"/home/user/security_report.md","message":"Complete"}`)
	first, err := fte.submitReport(t.Context(), 11, 12, args)
	require.NoError(t, err)
	require.Equal(t, validSubmission, first.Content)
	require.Len(t, db.logs, 1)
	docker.copyFromErr = errors.New("container removed")
	second, err := fte.submitReport(t.Context(), 11, 12, args)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Len(t, db.logs, 1)
	other, err := SubmittedReportForTask(t.Context(), db, 8, 11)
	require.NoError(t, err)
	require.Nil(t, other)
	other, err = SubmittedReportForTask(t.Context(), db, 7, 13)
	require.NoError(t, err)
	require.Nil(t, other)
	db.logs[0].Result = "tampered"
	_, err = SubmittedReportForTask(t.Context(), db, 7, 11)
	require.ErrorContains(t, err, "checksum")
}
func TestSubmitReportRejectionDoesNotFinishAgent(t *testing.T) {
	db := &submissionDB{}
	docker := &fakeDockerClient{readFileContent: "# Draft"}
	fte := &flowToolsExecutor{db: db, docker: docker, flowID: 7, cfg: &config.Config{}}
	noop := func(context.Context, string, json.RawMessage) (string, error) { return "", nil }
	accepted := 0
	ex, err := fte.GetPrimaryExecutor(PrimaryExecutorConfig{TaskID: 11, SubtaskID: 12, Barrier: noop, Adviser: noop, Coder: noop, Installer: noop, Memorist: noop, Pentester: noop, Searcher: noop, ReportSubmitted: func() { accepted++ }})
	require.NoError(t, err)
	ce := ex.(*customExecutor)
	args := json.RawMessage(`{"path":"/home/user/security_report.md","message":"Complete"}`)
	result, err := ce.handlers[SubmitReportToolName](t.Context(), SubmitReportToolName, args)
	require.NoError(t, err)
	require.Contains(t, result, "Report rejected")
	require.Empty(t, db.logs)
	require.Zero(t, accepted)
	require.False(t, ce.IsBarrierFunction(SubmitReportToolName))
	docker.copyFromErr = errdefs.ErrNotFound
	result, err = ce.handlers[SubmitReportToolName](t.Context(), SubmitReportToolName, args)
	require.NoError(t, err)
	require.Contains(t, result, "Report rejected: report file or its container is missing")
	require.Zero(t, accepted)
	require.False(t, ce.IsBarrierFunction(SubmitReportToolName))
	docker.copyFromErr = nil
	docker.readFileContent = validSubmission
	result, err = ce.handlers[SubmitReportToolName](t.Context(), SubmitReportToolName, args)
	require.NoError(t, err)
	require.Contains(t, result, "Report accepted")
	require.Equal(t, 1, accepted)
	require.True(t, ce.IsBarrierFunction(SubmitReportToolName))
}
