package lib

const (
	// String literals
	CommandName      string = "sst"
	FamilyName       string = "SeaStorage"
	FamilyVersion    string = "1.0"
	DistributionName string = "SeaStorage-Client"
	DefaultUrl       string = "http://127.0.0.1:8008"
	// Verbs
	VerbRegister        string = "register"
	VerbCreateDirectory string = "mkdir"
	VerbCreateFile      string = "touch"
	VerbUpdateFile      string = "update"
	VerbDeleteFile      string = "rm"
	VerbStoreFile       string = "store"
	// Content types
	ContentTypeOctetStream string = "application/octet-stream"
	ContentTypeJson        string = "application/json"
	// APIs
	BatchSubmitApi string = "batches"
	BatchStatusApi string = "batch_statuses"
	StateApi       string = "state"
	// Integer literals
	FamilyNamespaceAddressLength uint = 6
	FamilyVerbAddressLength      uint = 64
)
