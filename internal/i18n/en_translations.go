// Copyright © 2021 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package i18n

//revive:disable
var (
	MsgConfigFailed                 = ffm("FF10101", "Failed to read config")
	MsgTBD                          = ffm("FF10102", "TODO: Description")
	MsgJSONDecodeFailed             = ffm("FF10103", "Failed to decode input JSON")
	MsgAPIServerStartFailed         = ffm("FF10104", "Unable to start listener on %s: %s")
	MsgTLSConfigFailed              = ffm("FF10105", "Failed to initialize TLS configuration")
	MsgInvalidCAFile                = ffm("FF10106", "Invalid CA certificates file")
	MsgResponseMarshalError         = ffm("FF10107", "Failed to serialize response data", 400)
	MsgWebsocketClientError         = ffm("FF10108", "Error received from WebSocket client: %s")
	Msg404NotFound                  = ffm("FF10109", "Not found", 404)
	MsgUnknownBlockchainPlugin      = ffm("FF10110", "Unknown blockchain plugin: %s")
	MsgEthconnectRESTErr            = ffm("FF10111", "Error from ethconnect: %s")
	MsgDBInitFailed                 = ffm("FF10112", "Database initialization failed")
	MsgDBQueryBuildFailed           = ffm("FF10113", "Database query builder failed")
	MsgDBBeginFailed                = ffm("FF10114", "Database begin transaction failed")
	MsgDBQueryFailed                = ffm("FF10115", "Database query failed")
	MsgDBInsertFailed               = ffm("FF10116", "Database insert failed")
	MsgDBUpdateFailed               = ffm("FF10117", "Database update failed")
	MsgDBDeleteFailed               = ffm("FF10118", "Database delete failed")
	MsgDBCommitFailed               = ffm("FF10119", "Database commit failed")
	MsgDBMissingJoin                = ffm("FF10120", "Database missing expected join entry in table '%s' for id '%s'")
	MsgDBReadErr                    = ffm("FF10121", "Database resultset read error from table '%s'")
	MsgUnknownDatabasePlugin        = ffm("FF10122", "Unknown database plugin '%s'")
	MsgNullDataReferenceID          = ffm("FF10123", "Data id is null in message data reference %d")
	MsgDupDataReferenceID           = ffm("FF10124", "Duplicate data ID in message '%s'")
	MsgScanFailed                   = ffm("FF10125", "Failed to restore type '%T' into '%T'")
	MsgUnregisteredBatchType        = ffm("FF10126", "Unregistered batch type '%s'")
	MsgBatchDispatchTimeout         = ffm("FF10127", "Timed out dispatching work to batch")
	MsgInitializationNilDepError    = ffm("FF10128", "Initialization error due to unmet dependency")
	MsgNilResponseNon204            = ffm("FF10129", "No output from API call")
	MsgInvalidContentType           = ffm("FF10130", "Invalid content type", 415)
	MsgInvalidName                  = ffm("FF10131", "Field '%s' must be 1-64 characters, including alphanumerics (a-zA-Z0-9), dot (.), dash (-) and underscore (_), and must start/end in an alphanumeric", 400)
	MsgUnknownFieldValue            = ffm("FF10132", "Unknown %s '%v'", 400)
	MsgDataNotFound                 = ffm("FF10133", "Data not found for message %s", 400)
	MsgUnknownPublicStoragePlugin   = ffm("FF10134", "Unknown Public Storage plugin '%s'")
	MsgIPFSHashDecodeFailed         = ffm("FF10135", "Failed to decode IPFS hash into 32byte value '%s'")
	MsgIPFSRESTErr                  = ffm("FF10136", "Error from IPFS: %s")
	MsgSerializationFailed          = ffm("FF10137", "Serialization failed")
	MsgMissingPluginConfig          = ffm("FF10138", "Missing configuration '%s' for %s")
	MsgMissingDataHashIndex         = ffm("FF10139", "Missing data hash for index '%d' in message", 400)
	MsgMissingRequiredField         = ffm("FF10140", "Field '%s' is required", 400)
	MsgInvalidEthAddress            = ffm("FF10141", "Supplied ethereum address is invalid", 400)
	MsgInvalidUUID                  = ffm("FF10142", "Invalid UUID supplied", 400)
	Msg404NoResult                  = ffm("FF10143", "No result found", 404)
	MsgNilDataReferenceSealFail     = ffm("FF10144", "Invalid message: nil data reference at index %d", 400)
	MsgDupDataReferenceSealFail     = ffm("FF10145", "Invalid message: duplicate data reference at index %d", 400)
	MsgVerifyFailedInvalidHashes    = ffm("FF10146", "Invalid message: hashes do not match Hash=%s Expected=%s DataHash=%s DataHashExpected=%s", 400)
	MsgVerifyFailedNilHashes        = ffm("FF10147", "Invalid message: nil hashes", 400)
	MsgInvalidFilterField           = ffm("FF10148", "Unknown filter '%s'", 400)
	MsgInvalidValueForFilterField   = ffm("FF10149", "Unable to parse value for filter '%s'", 400)
	MsgUnsupportedSQLOpInFilter     = ffm("FF10150", "No SQL mapping implemented for filter operator '%s'", 400)
	MsgJSONObjectParseFailed        = ffm("FF10151", "Failed to parse '%s' as JSON")
	MsgFilterParamDesc              = ffm("FF10152", "Data filter field. Prefixes supported: > >= < <= @ ^ ! !@ !^")
	MsgSuccessResponse              = ffm("FF10153", "Success")
	MsgFilterSortDesc               = ffm("FF10154", "Sort field. For multi-field sort use comma separated values (or multiple query values) with '-' prefix for descending")
	MsgFilterDescendingDesc         = ffm("FF10155", "Descending sort order (overrides all fields in a multi-field sort)")
	MsgFilterSkipDesc               = ffm("FF10156", "The number of records to skip (max: %d). Unsuitable for bulk operations")
	MsgFilterLimitDesc              = ffm("FF10157", "The maximum number of records to return (max: %d)")
	MsgContextCanceled              = ffm("FF10158", "Context cancelled")
	MsgWSSendTimedOut               = ffm("FF10159", "Websocket send timed out")
	MsgWSClosing                    = ffm("FF10160", "Websocket closing")
	MsgWSConnectFailed              = ffm("FF10161", "Websocket connect failed")
	MsgInvalidURL                   = ffm("FF10162", "Invalid URL: '%s'")
	MsgDBMigrationFailed            = ffm("FF10163", "Database migration failed")
	MsgHashMismatch                 = ffm("FF10164", "Hash mismatch")
	MsgTimeParseFail                = ffm("FF10165", "Cannot parse time as RFC3339, Unix, or UnixNano: '%s'", 400)
	MsgDefaultNamespaceNotFound     = ffm("FF10166", "namespaces.default '%s' must be included in the namespaces.predefined configuration")
	MsgDurationParseFail            = ffm("FF10167", "Unable to parse '%s' as duration string, or millisecond number", 400)
	MsgEventTypesParseFail          = ffm("FF10168", "Unable to parse list of event types", 400)
	MsgUnknownEventType             = ffm("FF10169", "Unknown event type '%s'", 400)
	MsgIDMismatch                   = ffm("FF10170", "ID mismatch")
	MsgRegexpCompileFailed          = ffm("FF10171", "Unable to compile '%s' regexp '%s'")
	MsgUnknownEventTransportPlugin  = ffm("FF10172", "Unknown event transport plugin: %s")
	MsgWSConnectionNotActive        = ffm("FF10173", "Websocket connection '%s' no longer active")
	MsgWSSubAlreadyInFlight         = ffm("FF10174", "Websocket subscription '%s' already has a message in flight")
	MsgWSMsgSubNotMatched           = ffm("FF10175", "Acknowledgment does not match an inflight event + subscription")
	MsgWSClientSentInvalidData      = ffm("FF10176", "Invalid data")
	MsgWSClientUnknownAction        = ffm("FF10177", "Unknown action '%s'")
	MsgWSInvalidStartAction         = ffm("FF10178", "A start action must set namespace and either a name or ephemeral=true")
	MsgWSAutoAckChanged             = ffm("FF10179", "The autoack option must be set consistently on all start requests")
	MsgWSAutoAckEnabled             = ffm("FF10180", "The autoack option is enabled on this connection")
	MsgConnSubscriptionNotStarted   = ffm("FF10181", "Subscription %v is not started on connection")
	MsgDispatcherClosing            = ffm("FF10182", "Event dispatcher closing")
	MsgMaxFilterSkip                = ffm("FF10183", "You have reached the maximum pagination limit for this query (%d)")
	MsgMaxFilterLimit               = ffm("FF10184", "Your query exceeds the maximum filter limit (%d)")
	MsgAPIServerStaticFail          = ffm("FF10185", "An error occurred loading static content", 500)
	MsgEventListenerClosing         = ffm("FF10186", "Event listener closing")
	MsgNamespaceNotExist            = ffm("FF10187", "Namespace does not exist")
	MsgFieldTooLong                 = ffm("FF10188", "Field '%s' maximum length is %d", 400)
	MsgInvalidSubscription          = ffm("FF10189", "Invalid subscription", 400)
	MsgMismatchedTransport          = ffm("FF10190", "Connection ID '%s' appears not to be unique between transport '%s' and '%s'", 400)
	MsgInvalidFirstEvent            = ffm("FF10191", "Invalid firstEvent definition - must be 'newest','oldest' or a sequence number", 400)
	MsgNumberMustBeGreaterEqual     = ffm("FF10192", "Number must be greater than or equal to %d", 400)
	MsgAlreadyExists                = ffm("FF10193", "A %s with name '%s:%s' already exists", 409)
	MsgJSONValidatorBadRef          = ffm("FF10194", "Cannot use JSON validator for data with type '%s' and validator reference '%v'", 400)
	MsgDatatypeNotFound             = ffm("FF10195", "Datatype '%v' not found", 400)
	MsgSchemaLoadFailed             = ffm("FF10196", "Datatype '%s' schema invalid", 400)
	MsgDataCannotBeValidated        = ffm("FF10197", "Data cannot be validated", 400)
	MsgJSONDataInvalidPerSchema     = ffm("FF10198", "Data does not conform to the JSON schema of datatype '%s': %s", 400)
	MsgDataValueIsNull              = ffm("FF10199", "Data value is null", 400)
	MsgUnknownValidatorType         = ffm("FF10200", "Unknown validator type: '%s'", 400)
	MsgDataInvalidHash              = ffm("FF10201", "Invalid data: hashes do not match Hash=%s Expected=%s", 400)
	MsgSystemNSDescription          = ffm("FF10202", "FireFly system namespace")
	MsgNilID                        = ffm("FF10203", "ID is nil")
	MsgDataReferenceUnresolvable    = ffm("FF10204", "Data reference %d cannot be resolved", 400)
	MsgDataMissing                  = ffm("FF10205", "Data entry %d has neither 'id' to refer to existing data, or 'value' to include in-line JSON data", 400)
	MsgAuthorInvalid                = ffm("FF10206", "Invalid author specified", 400)
	MsgNoTransaction                = ffm("FF10207", "Message does not have a transaction", 404)
	MsgBatchNotSet                  = ffm("FF10208", "Message does not have an assigned batch", 404)
	MsgBatchNotFound                = ffm("FF10209", "Batch '%s' not found for message", 500)
	MsgBatchTXNotSet                = ffm("FF10210", "Batch '%s' does not have an assigned transaction", 404)
	MsgOwnerMissing                 = ffm("FF10211", "Owner missing", 400)
	MsgUnknownIdentityPlugin        = ffm("FF10212", "Unknown Identity plugin '%s'")
	MsgUnknownDataExchangePlugin    = ffm("FF10213", "Unknown Data Exchange plugin '%s'")
	MsgParentIdentityNotFound       = ffm("FF10214", "Organization with identity '%s' not found in identity chain for %s '%s'")
	MsgInvalidSigningIdentity       = ffm("FF10215", "Invalid signing identity")
	MsgNodeAndOrgIDMustBeSet        = ffm("FF10216", "node.name, org.name and org.identity must be configured first", 409)
	MsgBlobStreamingFailed          = ffm("FF10217", "Blob streaming terminated with error", 500)
	MsgMultiPartFormReadError       = ffm("FF10218", "Error reading multi-part form input", 400)
	MsgGroupMustHaveMembers         = ffm("FF10219", "Group must have at least one member", 400)
	MsgEmptyMemberIdentity          = ffm("FF10220", "Identity is blank in member %d")
	MsgEmptyMemberNode              = ffm("FF10221", "Node is blank in member %d")
	MsgDuplicateMember              = ffm("FF10222", "Member %d is a duplicate org+node combination")
	MsgOrgNotFound                  = ffm("FF10223", "Org with name or identity '%s' not found", 400)
	MsgNodeNotFound                 = ffm("FF10224", "Node with name or identity '%s' not found", 400)
	MsgLocalNodeResolveFailed       = ffm("FF10225", "Unable to find local node to add to group. Check the status API to confirm the node is registered", 500)
	MsgGroupNotFound                = ffm("FF10226", "Group '%s' not found", 404)
	MsgTooManyItems                 = ffm("FF10227", "Maximum number of %s items is %d (supplied=%d)", 400)
	MsgDuplicateArrayEntry          = ffm("FF10228", "Duplicate %s at index %d: '%s'", 400)
	MsgDXRESTErr                    = ffm("FF10229", "Error from data exchange: %s")
	MsgGroupInvalidHash             = ffm("FF10230", "Invalid group: hashes do not match Hash=%s Expected=%s", 400)
	MsgInvalidHex                   = ffm("FF10231", "Invalid hex supplied", 400)
	MsgInvalidWrongLenB32           = ffm("FF10232", "Byte length must be 32 (64 hex characters)", 400)
	MsgNodeNotFoundInOrg            = ffm("FF10233", "Unable to find any nodes owned by org '%s', or parent orgs", 400)
	MsgFilterAscendingDesc          = ffm("FF10234", "Ascending sort order (overrides all fields in a multi-field sort)")
	MsgPreInitCheckFailed           = ffm("FF10235", "Pre-initialization has not yet been completed. Add config records with the admin API complete initialization and reset the node")
	MsgFieldsAfterFile              = ffm("FF10236", "Additional form field sent after file in multi-part form (ignored): '%s'", 400)
	MsgDXBadResponse                = ffm("FF10237", "Unexpected '%s' in data exchange response: %s")
	MsgDXBadHash                    = ffm("FF10238", "Unexpected hash returned from data exchange upload. Hash=%s Expected=%s")
	MsgBlobNotFound                 = ffm("FF10239", "No blob has been uploaded or confirmed received, with hash=%s", 404)
	MsgDownloadBlobFailed           = ffm("FF10240", "Error download blob with reference '%s' from local data exchange")
	MsgDataDoesNotHaveBlob          = ffm("FF10241", "Data does not have a blob attachment", 404)
	MsgWebhookURLEmpty              = ffm("FF10242", "Webhook subscription option 'url' cannot be empty", 400)
	MsgWebhookInvalidStringMap      = ffm("FF10243", "Webhook subscription option '%s' must be map of string values. %s=%T", 400)
	MsgWebsocketsNoData             = ffm("FF10244", "Websockets subscriptions do not support streaming the full data payload, just the references (withData must be false)", 400)
	MsgWebhooksWithData             = ffm("FF10245", "Webhook subscriptions require the full data payload (withData must be true)", 400)
	MsgWebhooksOptURL               = ffm("FF10246", "Webhook url to invoke. Can be relative if a base URL is set in the webhook plugin config")
	MsgWebhooksOptMethod            = ffm("FF10247", "Webhook method to invoke. Default=POST")
	MsgWebhooksOptJSON              = ffm("FF10248", "Whether to assume the response body is JSON, regardless of the returned Content-Type")
	MsgWebhooksOptReply             = ffm("FF10249", "Whether to automatically send a reply event, using the body returned by the webhook")
	MsgWebhooksOptHeaders           = ffm("FF10250", "Static headers to set on the webhook request")
	MsgWebhooksOptQuery             = ffm("FF10251", "Static query params to set on the webhook request")
	MsgWebhooksOptInput             = ffm("FF10252", "A set of options to extract data from the first JSON input data in the incoming message. Only applies if withData=true")
	MsgWebhooksOptInputQuery        = ffm("FF10253", "A top-level property of the first data input, to use for query parameters")
	MsgWebhooksOptInputHeaders      = ffm("FF10254", "A top-level property of the first data input, to use for headers")
	MsgWebhooksOptInputBody         = ffm("FF10255", "A top-level property of the first data input, to use for the request body. Default is the whole first body")
	MsgWebhooksOptFastAck           = ffm("FF10256", "When true the event will be acknowledged before the webhook is invoked, allowing parallel invocations")
	MsgWebhooksReplyBadJSON         = ffm("FF10257", "Failed to process reply from webhook as JSON")
	MsgWebhooksOptReplyTag          = ffm("FF10258", "The tag to set on the reply message")
	MsgWebhooksOptReplyTx           = ffm("FF10259", "The transaction type to set on the reply message")
	MsgRequestTimeout               = ffm("FF10260", "The request with id '%s' timed out after %.2fms", 408)
	MsgRequestReplyTagRequired      = ffm("FF10261", "For request messages 'header.tag' must be set on the request message to route it to a suitable responder", 400)
	MsgRequestCannotHaveCID         = ffm("FF10262", "For request messages 'header.cid' must be unset", 400)
	MsgRequestTimeoutDesc           = ffm("FF10263", "Server-side request timeout (millseconds, or set a custom suffix like 10s)")
	MsgWebhooksOptInputPath         = ffm("FF10264", "A top-level property of the first data input, to use for a path to append with escaping to the webhook path")
	MsgWebhooksOptInputReplyTx      = ffm("FF10265", "A top-level property of the first data input, to use to dynamically set whether to pin the response (so the requester can choose)")
	MsgSystemTransportInternal      = ffm("FF10266", "You cannot create subscriptions on the system events transport")
	MsgFilterCountNotSupported      = ffm("FF10267", "This query does not support generating a count of all results")
	MsgFilterCountDesc              = ffm("FF10268", "Return a total count as well as items (adds extra database processing)")
	MsgRejected                     = ffm("FF10269", "Message with ID '%s' was rejected. Please check the FireFly logs for more information")
	MsgConfirmQueryParam            = ffm("FF10270", "When true the HTTP request blocks until the message is confirmed")
	MsgRequestMustBePrivate         = ffm("FF10271", "For request messages you must specify a group of private recipients", 400)
	MsgUnknownTokensPlugin          = ffm("FF10272", "Unknown tokens plugin '%s'", 400)
	MsgMissingTokensPluginConfig    = ffm("FF10273", "Invalid tokens configuration - name and connector are required", 400)
	MsgTokensRESTErr                = ffm("FF10274", "Error from tokens service: %s")
	MsgTokenPoolDuplicate           = ffm("FF10275", "Duplicate token pool")
	MsgTokenPoolRejected            = ffm("FF10276", "Token pool with ID '%s' was rejected. Please check the FireFly logs for more information")
	MsgAuthorNotFoundByDID          = ffm("FF10277", "Author could not be resolved via DID '%s'")
	MsgAuthorOrgNotFoundByName      = ffm("FF10278", "Author organization could not be resolved via name '%s'")
	MsgAuthorOrgSigningKeyMismatch  = ffm("FF10279", "Author organization '%s' is not associated with signing key '%s'")
	MsgCannotTransferToSelf         = ffm("FF10280", "From and to addresses must be different", 400)
	MsgLocalOrgLookupFailed         = ffm("FF10281", "Unable resolve the local org by the configured signing key on the node. Please confirm the org is registered with key '%s'", 500)
	MsgBigIntTooLarge               = ffm("FF10282", "Byte length of serialized integer is too large %d (max=%d)")
	MsgBigIntParseFailed            = ffm("FF10283", "Failed to parse JSON value '%s' into BigInt")
	MsgFabconnectRESTErr            = ffm("FF10284", "Error from fabconnect: %s")
	MsgInvalidIdentity              = ffm("FF10285", "Supplied Fabric signer identity is invalid", 400)
	MsgFailedToDecodeCertificate    = ffm("FF10286", "Failed to decode certificate: %s", 500)
	MsgInvalidMessageType           = ffm("FF10287", "Invalid message type - allowed types are %s", 400)
	MsgNoUUID                       = ffm("FF10288", "Field '%s' must not be a UUID", 400)
	MsgFetchDataDesc                = ffm("FF10289", "Fetch the data and include it in the messages returned", 400)
	MsgWSClosed                     = ffm("FF10290", "Websocket closed")
	MsgTokenTransferFailed          = ffm("FF10291", "Token transfer with ID '%s' failed. Please check the FireFly logs for more information")
	MsgFieldNotSpecified            = ffm("FF10292", "Field '%s' must be specified", 400)
	MsgTokenPoolNotConfirmed        = ffm("FF10293", "Token pool is not yet confirmed")
	MsgContractInterfaceExists      = ffm("FF10294", "A contract interface already exists in the namespace: '%s' with name: '%s' and version: '%s'", 409)
	MsgContractInterfaceNotFound    = ffm("FF10295", "Contract interface %s not found", 404)
	MsgContractMissingInputArgument = ffm("FF10296", "Missing required input argument '%s'", 400)
	MsgContractWrongInputType       = ffm("FF10297", "Input '%v' is of type '%v' not expected type of '%v'", 400)
	MsgContractMissingInputField    = ffm("FF10298", "Expected object of type '%v' to contain field named '%v' but it was missing", 400)
	MsgContractMapInputType         = ffm("FF10299", "Unable to map input type '%v' to known FireFly type - was expecting '%v'", 400)
	MsgContractByteDecode           = ffm("FF10300", "Unable to decode field '%v' as bytes", 400)
	MsgContractInternalType         = ffm("FF10301", "Input '%v' of type '%v' is not compatible blockchain internalType of '%v'", 400)
	MsgContractLocationInvalid      = ffm("FF10302", "Failed to validate contract location: %v", 400)
	MsgContractParamInvalid         = ffm("FF10303", "Failed to validate contract param: %v", 400)
)
