package main

// vim: set noexpandtab :

import (
	"database/sql"
	"errors"
	"fmt"
	//"io"
	"time"
	"github.com/gokyle/cryptobox/box"
)

const (
	challengeExpire int = 2 //minutes
	tokenExpire     int = 5 //minutes
)

var initSQL string = `
SET timezone TO UTC;
BEGIN;
CREATE TABLE IF NOT EXISTS users (
	id       bigserial NOT NULL UNIQUE PRIMARY KEY,
	name     varchar(255),
	pubKey   bytea,
	creation timestamp,
	admin    boolean
);
CREATE TABLE IF NOT EXISTS groups (
	id        bigserial NOT NULL UNIQUE PRIMARY KEY,
	name      varchar(255),
	admin     bigint[],
	member    bigint[],
	userGroup boolean
);
CREATE TABLE IF NOT EXISTS secret (
	id     bigserial NOT NULL UNIQUE PRIMARY KEY,
	uri    text,
	note   text,
	box    bytea,
	signer bigint
);
CREATE TABLE IF NOT EXISTS secretMap (
	id       bigserial NOT NULL UNIQUE PRIMARY KEY,
	isGroup  boolean,
	ownerId  bigint,
	secretId bigint
);
DROP TABLE IF EXISTS session;
CREATE TABLE session (
	id        bigint,
	token     bytea,
	challenge bytea,
	expire    timestamp
);
COMMIT; `

func dbInit(db *sql.DB) error {
	var err error
	_, err = db.Exec(initSQL)
	if err != nil {
		l.Println("error intializing database")
		return err
	}
	q = map[string]*sql.Stmt{}
	prepare := map[string]string{
		"getUser": "SELECT name, pubkey, creation, admin FROM users WHERE id = $1",
		"getUserIdByName": "SELECT id FROM users WHERE name = $1",
		"getGroup": "SELECT name, admin, member, userGroup FROM groups WHERE id = $1",
		"getGroupIdByName": "SELECT id FROM groups WHERE name = $1",
		"checkToken": "SELECT EXISTS (SELECT 1 FROM session WHERE id = $1 AND token = $2 AND expire < current_timestamp);",
		"checkChallenge": "SELECT EXISTS (SELECT 1 FROM session WHERE id = $1 AND challenge = $2 AND expire < current_timestamp);",
	}
	for name, query := range prepare {
		x, err := db.Prepare(query)
		if err != nil {
			l.Printf("error preparing: %s\t%s\n", name, query)
			return err
		}
		q[name] = x
	}
	return nil
}

// User bits
type User struct {
	Id       int64
	Name     string
	PubKey   *box.PublicKey
	Creation time.Time
	Admin    bool
}

func (u *User) String() string {
	return fmt.Sprintf("%x\t%s", u.Id, u.Name)
}

func (u *User) Save() error {
	var err error
	var r sql.Result
	var exists bool
	var id int64
	db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1);", u.Id).Scan(&exists)
	if !exists {
		r, err = db.Exec("INSERT INTO users (id, name, pubKey, creation, admin) VALUES ($1, $2, $3, $4, $5);",
			u.Id, u.Name, []byte(*u.PubKey), u.Creation, u.Admin)
	} else {
		return errors.New("user already exists")
	}
	if err != nil {
		return err
	}
	id, _ = r.LastInsertId()
	l.Printf("User.Save(): Last Insert Id: %x\n", id)
	return nil
}

// Group
type Group struct {
	Id       int64
	Name     string
	Admin    []int64
	Member   []int64
	UserGroup bool
}

func (g *Group) String() string {
	return fmt.Sprintf("%x\t%s", g.Id, g.Name)
}

func (g *Group) Save() error {
	var err error
	var r sql.Result
	var exists bool
	var id int64
	db.QueryRow("SELECT EXISTS (SELECT 1 FROM groups WHERE id = $1);", g.Id).Scan(&exists)
	if !exists {
		r, err = db.Exec("INSERT INTO groups (id, name, admin[1], member[1], userGroup) VALUES ($1, $2, $3, $4, $5);",
			g.Id, g.Name, g.Admin[0], g.Member[0], g.UserGroup)
	} else {
		return errors.New("group already exists")
	}
	if err != nil {
		return err
	}
	id, _ = r.LastInsertId()
	l.Printf("Group.Save(): Last Insert Id: %x\n", id)
	return nil
}

type SecretMap struct {
	Id       int64
	IsGroup  bool
	OwnerId  int64
	SecretId int64
}

func (sm *SecretMap) String() string {
	return fmt.Sprintf("%x\t%x\t%x", sm.Id, sm.OwnerId, sm.SecretId)
}

// Secret Bits
type Secret struct {
	Id     int64
	Uri    string
	Note   string
	//Meta   map[string]string
	Box    []byte
	Signer int64
}

func (s *Secret) String() string {
	return fmt.Sprintf("%x\t%s", s.Id, s.Uri)
}

// Token bits
type Token struct {
	Id   int64
	Data []byte
}

type Challenge struct {
	Id   int64
	Data []byte
}

//
// These are all methods for manipulating the datastore w/r/t the previously
// defined objects.
//

type orm struct {
	*sql.DB
	selUserById  *sql.Stmt
	selGroupById *sql.Stmt
	checkUserId  *sql.Stmt
	checkGroupId *sql.Stmt
	insChallenge *sql.Stmt
	insUser      *sql.Stmt
	insGroup     *sql.Stmt
	insUGM       *sql.Stmt
}

// Init prepares frequently used queries.
func (o *orm) Init() error {
	var err error
	// SELECTs
	o.selGroupById, err = o.Prepare("SELECT name, pubkey, cryptedPrivKey, admin FROM groups WHERE id = $1")
	if err != nil {
		return err
	}
	// Id checks. Used to determine when to INSERT or UPDATE
	o.checkUserId, err = o.Prepare("")
	if err != nil {
		return err
	}

	// INSERTs
	o.insUser, err = o.Prepare("INSERT INTO users (id, name, pubKey, creation, admin) VALUES (default, $1, $2, $3, $4);")
	if err != nil {
		return err
	}
	o.insGroup, err = o.Prepare("INSERT INTO groups (id, name, pubKey, cryptedPrivKey, hidden) VALUES (default, $1, $2, $3, $4);")
	if err != nil {
		return err
	}
	o.insUGM, err = o.Prepare("INSERT INTO ugm (id, userId, groupId, cryptedSymKey, admin) VALUES (default, $1, $2, $3, $4)")
	if err != nil {
		return err
	}

	// DELETEs
	// UPDATEs
	return nil
}

// This function is always used to actually return a User record.
// Other methods look up the id from the relevant bit of information and then call this.
func GetUser(id int64) (*User, error) {
	var err error
	var name string
	var key []byte
	var creation time.Time
	var admin bool
	err = q["getUser"].QueryRow(id).Scan(&name, &key, &creation, &admin)
	if err != nil {
		return nil, err
	}
	k := box.PublicKey(key)
	//return &User{id, name, der.(*box.PublicKey), creation, admin}, nil
	return &User{id, name, &k, creation, admin}, nil
}

func GetUserByName(name string) (*User, error) {
	var id int64
	var err error
	err = q["getUserIdByName"].QueryRow(name).Scan(&id)
	if err != nil {
		return nil, err
	}
	return GetUser(id)
}

// The following group methods are the same as their User counterparts
func GetGroup(id int64) (*Group, error) {
	var name string
	var admin []int64
	var member []int64
	var primary bool
	err := q["getGroup"].QueryRow(id).Scan(&name, &admin, &member, &primary)
	if err != nil {
		return nil, err
	}
	return &Group{id, name, admin, member, primary}, nil
}

func GetGroupByName(name string) (*Group, error) {
	var id int64
	var err error
	err = q["getGroupIdByName"].QueryRow(name).Scan(&id)
	if err != nil {
		return nil, err
	}
	return GetGroup(id)
}

func SaveToken(id int64, token []byte) error {
	expire := time.Now().UTC().Add(time.Duration(tokenExpire) * time.Minute)
	tx, err := db.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec("DELETE FROM session WHERE id = $1;", id)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec("INSERT INTO session (id, token, expire) VALUES ($1, $2, $3);", id, token, expire)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return err
	}
	return nil
}

func CheckToken(id int64, token []byte) bool {
	var ok bool
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM session WHERE id = $1 AND token = $2);", id, token).Scan(&ok)
	if err != nil {
		return false
	}
	return ok
}

func SaveChallenge(id int64, challenge []byte) error {
	expire := time.Now().UTC().Add(time.Duration(challengeExpire) * time.Minute)
	//_, err = tx.Exec("DELETE FROM session WHERE id = $1 AND token IS NULL;", id)
	//if err != nil {
	//	tx.Rollback()
	//	return err
	//}
	_, err := db.Exec("INSERT INTO session (id, challenge, expire) VALUES ($1, $2, $3);", id, challenge, expire)
	if err != nil {
		return err
	}
	return nil
}

func CheckChallenge(id int64, challenge []byte) bool {
	var ok bool
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM session WHERE id = $1 AND challenge = $2);", id, challenge).Scan(&ok)
	if err != nil {
		return false
	}
	return ok
}

//
// Higher order functions
//

func NewUser(name string, admin bool) (error, *User, *box.PrivateKey) {
	var err error
	var id int64
	id, err = nextId("user")
	priv, pub, ok := box.GenerateKey()
	if !ok {
		l.Println(err)
		return err, nil, nil
	}
	// cast so that we don't need to need to include cryptobox everywhere
	newUser := &User{Id: id, Name: name, PubKey: &pub, Creation: time.Now().UTC(), Admin: admin}
	err = newUser.Save()
	if err != nil {
		l.Println(err)
		return err, nil, nil
	}
	//l.Println("TODO: write out private key.", priv)
	return nil, newUser, &priv
}

func NewGroup(name string, primaryUserId int64, isUserGroup bool) (error, *Group) {
	var err error
	var nid int64
	nid, err = nextId("group")
	if err != nil {
		return err, nil
	}
	var newGroup *Group = &Group{ Id: nid, Name: name, Admin: []int64{primaryUserId},
		Member: []int64{primaryUserId}, UserGroup: isUserGroup }
	err = newGroup.Save()
	if err != nil {
		l.Println(err)
		return err, nil
	}
	return nil, newGroup
}
