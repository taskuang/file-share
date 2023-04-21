package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

type Lockbox struct {
	MarshaledAndEncryptedData		[]byte
	HMAC							[]byte
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username							string
	NamespaceSeedBytes					[]byte
	NamespaceKey						[]byte
	PKEDecryptionKey					userlib.PKEDecKey
	DSSignKey							userlib.DSSignKey
	OwnedFileAccessPointerKey			[]byte
	OwnedFileInfoSeedBytes				[]byte
	OwnedFileInfoKey					[]byte
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type OwnedFileInfo struct {
	ChildToFileAccessPointerUUID		map[string]userlib.UUID
}

type FileAccessPointerPointer struct {
	FileAccessPointerUUID	userlib.UUID
	FileAccessPointerKey	[]byte
}

type FileAccessPointer struct {
	FileAccessUUID	userlib.UUID
	FileAccessKey 	[]byte
}

type FileAccess struct {
	FileDataUUID		userlib.UUID
	FileDataKey			[]byte
}

type FileData struct {
	Owner		string
	NumAppends	int
	SeedBytes	[]byte
	ContentKey	[]byte
}

type Invitation struct {
	FileAccessPointerUUID		userlib.UUID
	FileAccessPointerKey		[]byte
}

type InvitationLockbox struct {
	MarshaledAndEncryptedInvitation		[]byte
	Signature							[]byte
}

// encrypt and mac object, wrap in lockbox, and store inside datastore
func storeObject(object interface{}, sourceKey []byte, UUID userlib.UUID) (err error) {
	marshaledObject, err := json.Marshal(object)  // marshal the object to be stored
	if err != nil {
		err = errors.New(strings.ToTitle("Marshal error"))
		return
	}
	encryptionKey, macKey, err := createEncryptionAndMacKey(sourceKey)  // create encryption + mac keys from source key
	if err != nil {
		err = errors.New(strings.ToTitle("HashKDF error"))
		return
	}
	var lockbox Lockbox
	iv := userlib.RandomBytes(16)
	encryptedObject := userlib.SymEnc(encryptionKey, iv, marshaledObject)  // encrypt and mac
	HMAC, err := userlib.HMACEval(macKey, encryptedObject)
	if err != nil {
		err = errors.New(strings.ToTitle("HMAC Eval error"))
		return
	}

	lockbox.MarshaledAndEncryptedData = encryptedObject  // populate lockbox fields
	lockbox.HMAC = HMAC

	marshaledLockbox, err := json.Marshal(lockbox)  // marshal lockbox
	if err != nil {
		err = errors.New(strings.ToTitle("Marshal error"))
		return
	}

	userlib.DatastoreSet(UUID, marshaledLockbox)  // store lockbox in datastore
	return
}

func fetchLockboxData(UUID userlib.UUID, sourceKey []byte) (data []byte, err error) {
	marshaledLockbox, ok := userlib.DatastoreGet(UUID)
	if !ok {
		err = errors.New(strings.ToTitle("Could not fetch object, nothing stored at this UUID"))
		return
	}
	var lockbox Lockbox
	err = json.Unmarshal(marshaledLockbox, &lockbox)

	encryptionKey, macKey, err := createEncryptionAndMacKey(sourceKey)  // create encryption + mac keys from source key
	if err != nil {
		err = errors.New(strings.ToTitle("HashKDF error"))
		return
	}

	recalculatedHMAC, err := userlib.HMACEval(macKey, lockbox.MarshaledAndEncryptedData)  // verify HMAC to ensure authenticity and integrity
	if err != nil {
		err = errors.New(strings.ToTitle("HMACEval error"))
		return
	}

	equal := userlib.HMACEqual(lockbox.HMAC, recalculatedHMAC)  
	if !equal {
		err = errors.New(strings.ToTitle("Datastore tampering has occurred"))
		return
	}

	data = userlib.SymDec(encryptionKey, lockbox.MarshaledAndEncryptedData)  // decrypt data and unmarshal into object
	return
}

func (userdata *User) fetchFileData(filename string) (filedata FileData, filedataUUID userlib.UUID, filedatakey []byte, err error) {
	fileaccesspointerpointerUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.NamespaceSeedBytes, []byte(filename)...))[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("FromBytes error"))
		return
	}
	fileaccesspointerpointerkey := userdata.NamespaceKey

	var fileaccesspointerpointer FileAccessPointerPointer  // fetch the correct fileaccesspointerpointer
	jsonData, err := fetchLockboxData(fileaccesspointerpointerUUID, fileaccesspointerpointerkey)
	if err != nil {
		err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
		return
	}
	err = json.Unmarshal(jsonData, &fileaccesspointerpointer)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}
	fileaccesspointerUUID := fileaccesspointerpointer.FileAccessPointerUUID  // get fileaccesspointer UUID/key
	fileaccesspointerkey := fileaccesspointerpointer.FileAccessPointerKey

	var fileaccesspointer FileAccessPointer
	jsonData, err = fetchLockboxData(fileaccesspointerUUID, fileaccesspointerkey)
	if err != nil {
		return
	}
	err = json.Unmarshal(jsonData, &fileaccesspointer)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}

	// fetch fileaccess instance from datastore. If we fail here, that this user is trying to fetchfiledata for a revoked file
	fileaccessUUID := fileaccesspointer.FileAccessUUID
	fileaccesskey := fileaccesspointer.FileAccessKey
	var fileaccess FileAccess
	jsonData, err = fetchLockboxData(fileaccessUUID, fileaccesskey)
	if err != nil {
		err = errors.New(strings.ToTitle("User had access permissions revoked"))
		return
	}
	err = json.Unmarshal(jsonData, &fileaccess)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}

	// get filedata UUID/Key from fileaccess. If we fail here, 
	filedataUUID = fileaccess.FileDataUUID
	filedatakey = fileaccess.FileDataKey

	jsonData, err = fetchLockboxData(filedataUUID, filedatakey)
	if err != nil {
		return
	}
	err = json.Unmarshal(jsonData, &filedata)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}
	return
}

// Uses a source/symmetric key to create an encryption and mac key using HashKDF
func createEncryptionAndMacKey(sourceKey []byte) (encryptionKey []byte, macKey []byte, err error) {
	encryptionKey, err = userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		err = errors.New(strings.ToTitle("HashKDF error"))
		return
	}
	macKey, err = userlib.HashKDF(sourceKey, []byte("mac"))
	if err != nil {
		err = errors.New(strings.ToTitle("HashKDF error"))
		return
	}
	return encryptionKey[:16], macKey[:16], err
}

func UserExists(username string, password string) (exists bool, UUID userlib.UUID, err error) {
	hash := userlib.Hash([]byte(username + password))  // create User's lockbox UUID
	UUID, err = uuid.FromBytes(hash[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("Cannot create User UUID"))
		return
	}

	_, exists = userlib.DatastoreGet(UUID)  // fetch User lockbox and see if it exists
	return
}


// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		err = errors.New(strings.ToTitle("User initialized with empty username"))
		return
	}
	
	exists, UUID, err := UserExists(username, password)  // check if user exists and also create user lockbox UUID
	if err != nil {
		return
	}

	if exists == true {
		err = errors.New(strings.ToTitle("User already exists"))
		return
	}

	var userdata User
	userdata.Username = username
	userdata.NamespaceSeedBytes = userlib.RandomBytes(16)
	userdata.NamespaceKey = userlib.RandomBytes(16)
	userdata.OwnedFileInfoSeedBytes = userlib.RandomBytes(16)
	userdata.OwnedFileInfoKey = userlib.RandomBytes(16)

	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()  // generate RSA asymmetric encryption keys and put in userdata/keystore
	if err != nil {
		err = errors.New(strings.ToTitle("PKEKeyGen error"))
		return
	}
	userdata.PKEDecryptionKey = PKEDecKey
	err = userlib.KeystoreSet(username + "PKEEncKey", PKEEncKey)
	if err != nil {
		err = errors.New(strings.ToTitle("Keystore set failed"))
		return
	}

	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()  // generate DS asymmetric signature keys and put in userdata/keystore
	if err != nil {
		err = errors.New(strings.ToTitle("DSKeyGen error"))
		return
	}
	userdata.DSSignKey = DSSignKey
	err = userlib.KeystoreSet(username + "DSVerifyKey", DSVerifyKey)

	if err != nil {
		err = errors.New(strings.ToTitle("Keystore set failed"))
		return
	}

	userdata.OwnedFileAccessPointerKey = userlib.RandomBytes(16)

	userKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	err = storeObject(userdata, userKey, UUID)  // NOT SURE WHAT TO PASS IN FOR *object OR STOREOBJECT'S PARAMETERS
	if err != nil {
		return
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	userKey := userlib.Argon2Key([]byte(password), []byte(username), 16)  // create User's lockbox key

	hash := userlib.Hash([]byte(username + password))  // create User's lockbox UUID
	userUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return
	}

	jsonData, err := fetchLockboxData(userUUID, userKey)
	if err != nil {
		return
	}
	err = json.Unmarshal(jsonData, &userdata)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// 1. create and store new filedata instance
	var filedata FileData 
	filedata.Owner = userdata.Username
	filedata.NumAppends = 1
	filedata.SeedBytes = userlib.RandomBytes(16)
	filedata.ContentKey = userlib.RandomBytes(16)

	filedataUUID := uuid.New()  // store filedata at filedataUUID with filedataKey as its lockbox's key
	filedatakey := userlib.RandomBytes(16)
	err = storeObject(filedata, filedatakey, filedataUUID)
	if err != nil {
		return
	}
	// end 1.

	// 2. create and store initial filecontent append
	fileContentSourceKey := userlib.Hash(append(filedata.SeedBytes, []byte(strconv.Itoa(0))...))[:16]  // generate fileContentUUID and fileContentKey
	fileContentUUIDBytes, err := userlib.HashKDF(fileContentSourceKey, []byte("UUID"))
	if err != nil {
		return
	}
	fileContentKey, err := userlib.HashKDF(fileContentSourceKey, []byte("key123123"))
	if err != nil {
		return
	}
	filecontentUUID, err := uuid.FromBytes(fileContentUUIDBytes[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("Cannot get filecontentUUID: FromBytes error"))
		return
	}
	err = storeObject(content, fileContentKey[:16], filecontentUUID)  // store content in data store with new filecontentUUID
	if err != nil {
		return
	}
	

	// end 2.

	// 3. create and store new fileaccess instance
	var fileaccess FileAccess // create fileaccess that points to filedata
	fileaccess.FileDataUUID = filedataUUID
	fileaccess.FileDataKey = filedatakey

	fileaccessUUID := uuid.New()  // store fileaccess at fileaccessUUID with fileaccessKey as its lockbox's key
	fileaccessKey := userlib.RandomBytes(16)
	err = storeObject(fileaccess, fileaccessKey, fileaccessUUID)
	if err != nil {
		return
	}
	// end 3.

	// 4. create and store new fileaccesspointer that points to fileaccess
	var fileaccesspointer FileAccessPointer
	fileaccesspointer.FileAccessUUID = fileaccessUUID
	fileaccesspointer.FileAccessKey = fileaccessKey

	fileaccesspointerUUID := uuid.New()  // store fileaccesspointer at fileaccesspointerUUID with OwnedFileAccessPointerKey as its lockbox's key
	fileaccesspointerkey := userdata.OwnedFileAccessPointerKey
	err = storeObject(fileaccesspointer, fileaccesspointerkey, fileaccesspointerUUID)
	if err != nil {
		return
	}
	// end 4.

	// 5. create a fileaccesspointerpointer with user's namespace information
	var fileaccesspointerpointer FileAccessPointerPointer
	fileaccesspointerpointer.FileAccessPointerUUID = fileaccesspointerUUID
	fileaccesspointerpointer.FileAccessPointerKey = fileaccesspointerkey

	fileaccesspointerpointerUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.NamespaceSeedBytes, []byte(filename)...))[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
		return
	}
	fileaccesspointerpointerkey := userdata.NamespaceKey
	err = storeObject(fileaccesspointerpointer, fileaccesspointerpointerkey, fileaccesspointerpointerUUID)
	if err != nil {
		return
	}
	// end 5.

	// 6. create and store new ownedfileinfo with owner as an entry as child too
	var ownedfileinfo OwnedFileInfo
	ownedfileinfo.ChildToFileAccessPointerUUID = make(map[string]userlib.UUID)
	ownedfileinfo.ChildToFileAccessPointerUUID[userdata.Username] = fileaccesspointerUUID

	ownedfileinfoUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.OwnedFileInfoSeedBytes, []byte(filename)...))[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("ownedfileinfoUUID FromBytes Error"))
		return
	}
	ownedfileinfokey := userdata.OwnedFileInfoKey
	err = storeObject(ownedfileinfo, ownedfileinfokey, ownedfileinfoUUID)
	if err != nil {
		return
	}
	// end 6.


	return
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	if content == nil { // if empty byte sequence, don't do anything
		return
	}

	filedata, filedataUUID, filedatakey, err := userdata.fetchFileData(filename)
	if err != nil {
		return
	}

	fileContentSourceKey := userlib.Hash(append(filedata.SeedBytes, []byte(strconv.Itoa(filedata.NumAppends))...))[:16]  // generate fileContentUUID and fileContentKey
	fileContentUUIDBytes, err := userlib.HashKDF(fileContentSourceKey, []byte("UUID"))
	if err != nil {
		return
	}
	fileContentKey, err := userlib.HashKDF(fileContentSourceKey, []byte("key123123"))
	if err != nil {
		return
	}
	filecontentUUID, err := uuid.FromBytes(fileContentUUIDBytes[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("Cannot get filecontentUUID: FromBytes error"))
		return
	}
	err = storeObject(content, fileContentKey[:16], filecontentUUID)  // store content in data store with new filecontentUUID
	if err != nil {
		return
	}
	filedata.NumAppends = filedata.NumAppends + 1
	err = storeObject(filedata, filedatakey, filedataUUID)  // increment number of appends in fileData and restore in data store
	if err != nil {
		return
	}


	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	filedata, _, _, err := userdata.fetchFileData(filename)
	if err != nil {
		return
	}

	
	for i := 0; i < filedata.NumAppends; i++ {



		fileContentSourceKey := userlib.Hash(append(filedata.SeedBytes, []byte(strconv.Itoa(i))...))[:16]  // generate fileContentUUID and fileContentKey
		fileContentUUIDBytes, err := userlib.HashKDF(fileContentSourceKey, []byte("UUID"))
		if err != nil {
			return nil, err
		}
		fileContentKey, err := userlib.HashKDF(fileContentSourceKey, []byte("key123123"))
		if err != nil {
			return nil, err
		}
		filecontentUUID, err := uuid.FromBytes(fileContentUUIDBytes[:16])
		if err != nil {
			err = errors.New(strings.ToTitle("Cannot get filecontentUUID: FromBytes error"))
			return nil, err
		}
	

		// fetch filedata from datastore
		var pieceoffilecontent []byte
		jsonData, err := fetchLockboxData(filecontentUUID, fileContentKey[:16])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(jsonData, &pieceoffilecontent)
		if err != nil {
			err = errors.New(strings.ToTitle("Unmarshal error"))
			return nil, err
		}
		
		content = append(content, pieceoffilecontent...)
	}
	return
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {  // creating invitation is just creating an invitation with sender string, fileaccesspointerUUID, fileaccesspointerkey

	// 1. get back fileaccess and filedata info
	fileaccesspointerpointerUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.NamespaceSeedBytes, []byte(filename)...))[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("FromBytes error"))
		return
	}
	fileaccesspointerpointerkey := userdata.NamespaceKey

	var fileaccesspointerpointer FileAccessPointerPointer  // fetch the correct fileaccesspointerpointer
	jsonData, err := fetchLockboxData(fileaccesspointerpointerUUID, fileaccesspointerpointerkey)
	if err != nil {
		err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
		return
	}
	err = json.Unmarshal(jsonData, &fileaccesspointerpointer)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}
	fileaccesspointerUUID := fileaccesspointerpointer.FileAccessPointerUUID  // get fileaccesspointer UUID/key
	fileaccesspointerkey := fileaccesspointerpointer.FileAccessPointerKey

	var fileaccesspointer FileAccessPointer
	jsonData, err = fetchLockboxData(fileaccesspointerUUID, fileaccesspointerkey)
	if err != nil {
		return
	}
	err = json.Unmarshal(jsonData, &fileaccesspointer)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}

	// fetch fileaccess instance from datastore. If we fail here, that this user is trying to fetchfiledata for a revoked file
	fileaccessUUID := fileaccesspointer.FileAccessUUID
	fileaccesskey := fileaccesspointer.FileAccessKey
	var fileaccess FileAccess
	jsonData, err = fetchLockboxData(fileaccessUUID, fileaccesskey)
	if err != nil {
		err = errors.New(strings.ToTitle("User had access permissions revoked"))
		return
	}
	err = json.Unmarshal(jsonData, &fileaccess)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return uuid.Nil, err
	}

	// get filedata UUID/Key from fileaccess. If we fail here, 
	filedataUUID := fileaccess.FileDataUUID
	filedatakey := fileaccess.FileDataKey

	var filedata FileData
	jsonData, err = fetchLockboxData(filedataUUID, filedatakey)
	if err != nil {
		return uuid.Nil, err
	}
	err = json.Unmarshal(jsonData, &filedata)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return uuid.Nil, err
	}
	// end 1.

	// 2. create or get fileaccesspointer UUID/Key
	if userdata.Username == filedata.Owner {  // sharer is owner, so create new fileaccesspointer UUID/Key to share
		var fileaccesspointer FileAccessPointer // create new fileaccesspointer that points to fileaccess
		fileaccesspointer.FileAccessUUID = fileaccessUUID
		fileaccesspointer.FileAccessKey = fileaccesskey

		fileaccesspointerUUID = uuid.New()  // store fileaccesspointer at fileaccesspointerUUID with OwnedFileAccessPointerKey as its lockbox's key
		fileaccesspointerkey = userdata.OwnedFileAccessPointerKey
		err = storeObject(fileaccesspointer, fileaccesspointerkey, fileaccesspointerUUID)
		if err != nil {
			return uuid.Nil, err
		}
	} else {  // sharer is not owner, fetch fileaccesspointerpointer in order to get fileaccesspointer UUID/Key to share
		fileaccesspointerpointerUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.NamespaceSeedBytes, []byte(filename)...))[:16])  
		if err != nil {
			err = errors.New(strings.ToTitle("FromBytes error"))
			return uuid.Nil, err
		}
		fileaccesspointerpointerkey := userdata.NamespaceKey

		var fileaccesspointerpointer FileAccessPointerPointer 
		jsonData, err := fetchLockboxData(fileaccesspointerpointerUUID, fileaccesspointerpointerkey)
		if err != nil {
			err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
			return uuid.Nil, err
		}
		err = json.Unmarshal(jsonData, &fileaccesspointerpointer)
		if err != nil {
			err = errors.New(strings.ToTitle("Unmarshal error"))
			return uuid.Nil, err
		}
		fileaccesspointerUUID = fileaccesspointerpointer.FileAccessPointerUUID  // get fileaccesspointer UUID/key
		fileaccesspointerkey = fileaccesspointerpointer.FileAccessPointerKey
	}

	// end 2.

	// 3. create and store invitation instance
	var invitation Invitation
	invitation.FileAccessPointerUUID = fileaccesspointerUUID
	invitation.FileAccessPointerKey = fileaccesspointerkey

	recipientPublicEncryptionKey, ok := userlib.KeystoreGet(recipientUsername + "PKEEncKey")
	if !ok {
		err = errors.New(strings.ToTitle("Recipient username doesn't exist"))
		return
	}

	marshaledInvitation, err := json.Marshal(invitation)
	if err != nil {
		err = errors.New(strings.ToTitle("Marshal error"))
		return
	}

	encryptedInvitation, err := userlib.PKEEnc(recipientPublicEncryptionKey, marshaledInvitation)
	if err != nil {
		
		return
	}

	signature, err := userlib.DSSign(userdata.DSSignKey, encryptedInvitation)

	var invitationlockbox InvitationLockbox
	invitationlockbox.MarshaledAndEncryptedInvitation = encryptedInvitation
	invitationlockbox.Signature = signature

	invitationPtr = uuid.New()

	marshaledInvitationLockbox, err := json.Marshal(invitationlockbox)
	if err != nil {
		err = errors.New(strings.ToTitle("Marshal error"))
		return
	}

	userlib.DatastoreSet(invitationPtr, marshaledInvitationLockbox)
	// end 3.

	// 4. if creator is file owner, get back ownedfileinfo, update info inside, then store it again
	if userdata.Username == filedata.Owner { 
		ownedfileinfoUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.OwnedFileInfoSeedBytes, []byte(filename)...))[:16])
		if err != nil {
			err = errors.New(strings.ToTitle("FromBytes error"))
			return uuid.Nil, err
		}
		ownedfileinfokey := userdata.OwnedFileInfoKey

		var ownedfileinfo OwnedFileInfo  // fetch ownedfileinfo
		jsonData, err := fetchLockboxData(ownedfileinfoUUID, ownedfileinfokey)
		if err != nil {
			err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
			return uuid.Nil, err
		}
		err = json.Unmarshal(jsonData, &ownedfileinfo)
		if err != nil {
			err = errors.New(strings.ToTitle("Unmarshal error"))
			return uuid.Nil, err
		}
		ownedfileinfo.ChildToFileAccessPointerUUID[recipientUsername] = fileaccesspointerUUID
		err = storeObject(ownedfileinfo, ownedfileinfokey, ownedfileinfoUUID)
		if err != nil {
			return uuid.Nil, err
		}
	}
	// end 4.
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {

	// 1. retrieve invitation from datastore
	marshaledinvitationlockbox, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		err = errors.New(strings.ToTitle("No invitation at this UUID"))
		return
	}
	senderDSVerifyKey, ok := userlib.KeystoreGet(senderUsername + "DSVerifyKey")
	if !ok {
		err = errors.New(strings.ToTitle("Sender doesn't exist"))
		return
	}

	// unmarshal the invitationlockbox
	var invitationlockbox InvitationLockbox
	err = json.Unmarshal(marshaledinvitationlockbox, &invitationlockbox)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}
	// confirm signature of this lockbox with sender's public key
	err = userlib.DSVerify(senderDSVerifyKey, invitationlockbox.MarshaledAndEncryptedInvitation, invitationlockbox.Signature)
	if err != nil {
		err = errors.New(strings.ToTitle("Datastore tampering has occurred in Accept Invitation or wrong sender"))
		return
	}

	// decrypt invitation with recipient's private key
	marshaledinvitation, err := userlib.PKEDec(userdata.PKEDecryptionKey, invitationlockbox.MarshaledAndEncryptedInvitation)
	if err != nil {
		err = errors.New(strings.ToTitle("Wrong recipient: Cannot decrypt invitatonlockbox in Accept Invitation"))
		return
	}

	// unmarshal the invitation
	var invitation Invitation
	err = json.Unmarshal(marshaledinvitation, &invitation)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}

	// end 1.

	// 2. update namespace of recipient by creating fileaccesspointerpointer and putting into datastore
	var fileaccesspointerpointer FileAccessPointerPointer
	fileaccesspointerpointer.FileAccessPointerUUID = invitation.FileAccessPointerUUID
	fileaccesspointerpointer.FileAccessPointerKey = invitation.FileAccessPointerKey

	fileaccesspointerpointerUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.NamespaceSeedBytes, []byte(filename)...))[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
		return
	}

	fileaccesspointerpointerkey := userdata.NamespaceKey
	err = storeObject(fileaccesspointerpointer, fileaccesspointerpointerkey, fileaccesspointerpointerUUID)
	if err != nil {
		return
	}
	// end 2.

	// 3. if owner shared the file, update their child map with recipient and new fileaccesspointerUUID
	filedata, _, _, err := userdata.fetchFileData(filename)
	if err != nil {
		return
	}

	if filedata.Owner == senderUsername {
		
	}
	// end 3.

	return
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {

	// 1. get back fileaccess and filedata info
	fileaccesspointerpointerUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.NamespaceSeedBytes, []byte(filename)...))[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("FromBytes error"))
		return
	}
	fileaccesspointerpointerkey := userdata.NamespaceKey

	var fileaccesspointerpointer FileAccessPointerPointer  // fetch the correct fileaccesspointerpointer
	jsonData, err := fetchLockboxData(fileaccesspointerpointerUUID, fileaccesspointerpointerkey)
	if err != nil {
		err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
		return
	}
	err = json.Unmarshal(jsonData, &fileaccesspointerpointer)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}
	fileaccesspointerUUID := fileaccesspointerpointer.FileAccessPointerUUID  // get fileaccesspointer UUID/key
	fileaccesspointerkey := fileaccesspointerpointer.FileAccessPointerKey

	var fileaccesspointer FileAccessPointer
	jsonData, err = fetchLockboxData(fileaccesspointerUUID, fileaccesspointerkey)
	if err != nil {
		return
	}
	err = json.Unmarshal(jsonData, &fileaccesspointer)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return
	}

	// fetch fileaccess instance from datastore. If we fail here, that this user is trying to fetchfiledata for a revoked file
	fileaccessUUID := fileaccesspointer.FileAccessUUID
	fileaccesskey := fileaccesspointer.FileAccessKey
	var fileaccess FileAccess
	jsonData, err = fetchLockboxData(fileaccessUUID, fileaccesskey)
	if err != nil {
		err = errors.New(strings.ToTitle("User had access permissions revoked"))
		return
	}
	err = json.Unmarshal(jsonData, &fileaccess)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return err
	}

	// get filedata UUID/Key from fileaccess. If we fail here, 
	filedataUUID := fileaccess.FileDataUUID
	filedatakey := fileaccess.FileDataKey

	var filedata FileData
	jsonData, err = fetchLockboxData(filedataUUID, filedatakey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jsonData, &filedata)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return err
	}
	// end 1.

	// 2. verify that this user has a file with filename + is the owner
	if err != nil {
		err = errors.New(strings.ToTitle("File does not exist in this user's namespace"))
		return
	}
	if filedata.Owner != userdata.Username {
		err = errors.New(strings.ToTitle("User is not owner of this file"))
		return
	}
	// end 2.


	// 3. generate new filedatakey and reencrypt/store filedata
	filedatakey = userlib.RandomBytes(16)
	err = storeObject(filedata, filedatakey, filedataUUID)
	if err != nil {
		return
	}
	// end 3.

	// 4. give filedatakey to fileaccess, generate new fileaccesskey and reencrypt/store fileaccess
	fileaccess.FileDataKey = filedatakey
	fileaccesskey = userlib.RandomBytes(16)
	err = storeObject(fileaccess, fileaccesskey, fileaccessUUID)
	if err != nil {
		return
	}
	// end 4.

	// 5. get back ownedfileinfo
	ownedfileinfoUUID, err := uuid.FromBytes(userlib.Hash(append(userdata.OwnedFileInfoSeedBytes, []byte(filename)...))[:16])
	if err != nil {
		err = errors.New(strings.ToTitle("FromBytes error"))
		return err
	}
	ownedfileinfokey := userdata.OwnedFileInfoKey

	var ownedfileinfo OwnedFileInfo  // fetch ownedfileinfo
	jsonData, err = fetchLockboxData(ownedfileinfoUUID, ownedfileinfokey)
	if err != nil {
		err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
		return err
	}
	err = json.Unmarshal(jsonData, &ownedfileinfo)
	if err != nil {
		err = errors.New(strings.ToTitle("Unmarshal error"))
		return err
	}
	// end 5.

	// 6. distribute fileaccesskey to all fileaccesspointers and reencrypt/store all fileaccesspointers
	for childusername, fileaccesspointerUUID := range ownedfileinfo.ChildToFileAccessPointerUUID {
		if childusername != recipientUsername {
			var fileaccesspointer FileAccessPointer  // fetch fileaccesspointer
			jsonData, err = fetchLockboxData(fileaccesspointerUUID, userdata.OwnedFileAccessPointerKey)
			if err != nil {
				err = errors.New(strings.ToTitle("User has no file with filename in namespace"))
				return err
			}
			err = json.Unmarshal(jsonData, &fileaccesspointer)
			if err != nil {
				err = errors.New(strings.ToTitle("Unmarshal error"))
				return err
			}

			// update fileaccesspointer's fileaccesskeys and reencrypt/restore it
			fileaccesspointer.FileAccessKey = fileaccesskey
			err = storeObject(fileaccesspointer, userdata.OwnedFileAccessPointerKey, fileaccesspointerUUID)
			if err != nil {
				return
			}
		}
	}
	// end 6.
	return






	return nil
}
