package core

// AppView is the complete public bridge contract. It contains no sessions,
// subscription URLs, proxy addresses or credentials.
type NodeView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Group      string   `json:"group"`
	Region     *string  `json:"region"`
	Protocol   string   `json:"protocol"`
	Compatible bool     `json:"compatible"`
	Reason     *string  `json:"reason"`
	Latency    *float64 `json:"latency"`
	Probe      string   `json:"probe"`
}
type AccountView struct {
	Email      string  `json:"email"`
	PlanName   string  `json:"planName"`
	ExpiryKind string  `json:"expiryKind"`
	ExpiresAt  *string `json:"expiresAt"`
	QuotaKind  string  `json:"quotaKind"`
	UsedBytes  *string `json:"usedBytes"`
	QuotaBytes *string `json:"quotaBytes"`
	ObservedAt string  `json:"observedAt"`
	Status     string  `json:"status"`
}
type ViewLinks struct {
	Website bool `json:"website"`
	Renew   bool `json:"renew"`
	Help    bool `json:"help"`
	Support bool `json:"support"`
}
type AppView struct {
	Brand        string          `json:"brand"`
	Version      string          `json:"version"`
	Environment  string          `json:"environment"`
	Demo         bool            `json:"demo"`
	LoggedIn     bool            `json:"loggedIn"`
	Account      *AccountView    `json:"account"`
	Connection   ConnectionState `json:"connection"`
	SelectedNode *string         `json:"selectedNode"`
	ActualNode   *string         `json:"actualNode"`
	Sync         string          `json:"sync"`
	LastSync     *int64          `json:"lastSync"`
	UsableUntil  *int64          `json:"usableUntil"`
	Error        *ErrorCode      `json:"error"`
	Nodes        []NodeView      `json:"nodes"`
	Preferences  Preferences     `json:"preferences"`
	Storage      string          `json:"storage"`
	HelperReady  bool            `json:"helperReady"`
	ProxyPort    int             `json:"proxyPort"`
	Policy       string          `json:"policy"`
	Announcement *string         `json:"announcement"`
	UpdateError  *ErrorCode      `json:"updateError"`
	Update       string          `json:"update"`
	ManualUpdate bool            `json:"manualUpdate"`
	// Installing: the user asked to update; the download (if any) and installation run
	// on their own and the app restarts into the new version.
	Installing         bool         `json:"installing"`
	PendingRenewal     bool         `json:"pendingRenewal"`
	Download           DownloadView `json:"download"`
	Rules              string       `json:"rules"`
	ShowTrafficSummary bool         `json:"showTrafficSummary"`
	Links              ViewLinks    `json:"links"`
	Report             ReportView   `json:"report"`
	ReportAvailable    bool         `json:"reportAvailable"`
	// Signup is what the panel asks of a new account, once the sign-up form asked; null
	// before that or when the panel could not be reached.
	Signup *SignupConfig `json:"signup"`
	// Invite is the account's invite code once asked for; null before that.
	Invite *InviteView `json:"invite"`
	Now    int64       `json:"now"`
}

// ReportView is the state of the user's problem report: idle, sending, sent (with the
// code to give support) or failed.
type ReportView struct {
	Status string  `json:"status"`
	Code   *string `json:"code"`
}
type CommandResult struct {
	OK    bool      `json:"ok"`
	State AppView   `json:"state"`
	Error ErrorCode `json:"error,omitempty"`
	// Message is the panel's own explanation of a refusal, e.g. "邀请码无效".
	Message string `json:"message,omitempty"`
}
