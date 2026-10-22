package model

// AgentsConfig keeps write-only provider credentials out of the GraphQL output schema.
type AgentsConfig struct {
	BaseURL      *string      `json:"baseUrl,omitempty"`
	APIKey       *string      `json:"apiKey,omitempty"`
	Simple       *AgentConfig `json:"simple"`
	SimpleJSON   *AgentConfig `json:"simpleJson"`
	PrimaryAgent *AgentConfig `json:"primaryAgent"`
	Assistant    *AgentConfig `json:"assistant"`
	Generator    *AgentConfig `json:"generator"`
	Refiner      *AgentConfig `json:"refiner"`
	Adviser      *AgentConfig `json:"adviser"`
	Reflector    *AgentConfig `json:"reflector"`
	Searcher     *AgentConfig `json:"searcher"`
	Enricher     *AgentConfig `json:"enricher"`
	Coder        *AgentConfig `json:"coder"`
	Installer    *AgentConfig `json:"installer"`
	Pentester    *AgentConfig `json:"pentester"`
}
