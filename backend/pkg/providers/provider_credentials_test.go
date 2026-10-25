package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/database/converter"
	"pentagi/pkg/graph/model"
	"pentagi/pkg/providers/pconfig"
	"pentagi/pkg/providers/provider"

	"github.com/stretchr/testify/require"
)

type credentialProviderStore struct{ database.Querier }

func (credentialProviderStore) CreateProvider(_ context.Context, p database.CreateProviderParams) (database.Provider, error) {
	return database.Provider{ID: 1, UserID: p.UserID, Name: p.Name, Type: p.Type, Config: p.Config}, nil
}

// Exercise GraphQL input conversion, provider persistence, reconstruction and a real HTTP model call.
func TestSavedProviderCredentialsReachModelServer(t *testing.T) {
	for _, protocol := range []provider.ProviderType{provider.ProviderOpenAI, provider.ProviderAnthropic, provider.ProviderGemini} {
		for _, environment := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/environment=%t", protocol, environment), func(t *testing.T) {
				var unexpected atomic.Int32
				fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					unexpected.Add(1)
					http.Error(w, "wrong server", http.StatusUnauthorized)
				}))
				defer fallback.Close()
				cfg := &config.Config{HTTPClientTimeout: 5}
				if environment {
					cfg.OpenAIKey, cfg.OpenAIServerURL = "environment-key", fallback.URL
					cfg.AnthropicAPIKey, cfg.AnthropicServerURL = "environment-key", fallback.URL
					cfg.GeminiAPIKey, cfg.GeminiServerURL = "environment-key", fallback.URL
				}
				original := *cfg
				defaults, skipped, err := buildDefaultConfigs(cfg)
				require.NoError(t, err)
				pc := &providerController{cfg: cfg, db: credentialProviderStore{}, Providers: provider.Providers{}, defaultConfigs: defaults, defaultConfigErrors: skipped}
				if environment {
					pc.Providers["default"] = stubTypedProvider{ptype: protocol}
				}
				// Distinct saved providers must not overwrite each other's endpoint or key.
				for _, identity := range []string{"first", "second"} {
					key := identity + "-key"
					modelName := map[provider.ProviderType]string{provider.ProviderOpenAI: "gpt-4o", provider.ProviderAnthropic: "claude-3-5-sonnet-latest", provider.ProviderGemini: "gemini-2.0-flash"}[protocol]
					var calls atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						var body map[string]any
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
						}
						w.Header().Set("Content-Type", "application/json")
						switch protocol {
						case provider.ProviderOpenAI:
							if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer "+key || body["model"] != modelName || body["messages"] == nil {
								t.Errorf("incorrect OpenAI request: path=%s model=%v", r.URL.Path, body["model"])
							}
							fmt.Fprint(w, `{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
						case provider.ProviderAnthropic:
							if r.URL.Path != "/v1/messages" || r.Header.Get("X-Api-Key") != key || r.Header.Get("Anthropic-Version") == "" || body["model"] != modelName || body["messages"] == nil {
								t.Errorf("incorrect Anthropic request: path=%s model=%v", r.URL.Path, body["model"])
							}
							fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
						case provider.ProviderGemini:
							if !strings.HasSuffix(r.URL.Path, "/models/"+modelName+":generateContent") || r.Header.Get("X-Goog-Api-Key") != key || body["contents"] == nil {
								t.Errorf("incorrect Gemini request: path=%s", r.URL.Path)
							}
							fmt.Fprint(w, `{"candidates":[{"content":{"parts":[{"text":"ok"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}`)
						}
					}))
					defer server.Close()
					baseURL := server.URL
					if protocol == provider.ProviderOpenAI || protocol == provider.ProviderAnthropic {
						baseURL += "/v1"
					}
					input := converter.ConvertAgentsConfigFromGqlModel(&model.AgentsConfig{BaseURL: &baseURL, APIKey: &key, Simple: &model.AgentConfig{Model: modelName}})
					row, err := pc.CreateProvider(context.Background(), 1, provider.ProviderName(identity), protocol, input)
					require.NoError(t, err)
					prv, err := pc.NewProvider(row)
					require.NoError(t, err)
					require.Equal(t, protocol, prv.Type())
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					answer, err := prv.Call(ctx, pconfig.OptionsTypeSimple, "say ok")
					cancel()
					require.NoError(t, err)
					require.Equal(t, "ok", answer)
					require.EqualValues(t, 1, calls.Load())
				}
				require.Zero(t, unexpected.Load(), "saved provider called the environment endpoint")
				require.Equal(t, original, *cfg, "provider credentials mutated shared configuration")
			})
		}
	}
}
