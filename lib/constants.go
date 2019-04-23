package lib

const (
	// String literals
	CommandName      string = "sst"
	FamilyName       string = "SeaStorage"
	FamilyVersion    string = "1.0"
	DistributionName string = "SeaStorage-ClientFramework"
	DefaultUrl       string = "http://127.0.0.1:8008"
	// Content types
	ContentTypeOctetStream string = "application/octet-stream"
	ContentTypeJson        string = "application/json"
	// APIs
	BatchSubmitApi string = "batches"
	BatchStatusApi string = "batch_statuses"
	StateApi       string = "state"
	// Verbs
	VerbRegister        string = "register"
	VerbCreateDirectory string = "mkdir"
	VerbCreateFile      string = "touch"
	VerbRename          string = "rename"
	VerbUpdateFileInfo  string = "update-info"
	VerbUpdateFileKey   string = "update-key"
	VerbShareFiles      string = "share"
	VerbPublicKey       string = "public"
	VerbStoreFile       string = "store"
	VerbDeleteFiles     string = "rm"
	VerbListDirectory   string = "ls"
)
