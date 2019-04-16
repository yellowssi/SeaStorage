package internal

const (
	// String literals
	FAMILY_NAME       string = "SeaStorage"
	FAMILY_VERSION    string = "1.0"
	DISTRIBUTION_NAME string = "SeaStorage-Client"
	DEFAULT_URL       string = "http://127.0.0.1:8008"
	// Verbs
	VERB_REGISTER         string = "register"
	VERB_CREATE_DIRECTORY string = "mkdir"
	VERB_CREATE_FILE      string = "touch"
	VERB_UPDATE_FILE      string = "update"
	VERB_DELETE_FILE	  string = "rm"
	VERB_STORE_FILE       string = "store"
	// APIs
	BATCH_SUBMIT_API string = "batches"
	BATCH_STATUS_API string = "batch_statuses"
	STATE_API        string = "state"
	// Integer literals
	FAMILY_NAMESPACE_ADDRESS_LENGTH uint = 6
	FAMILY_VERB_ADDRESS_LENGTH      uint = 64
)
