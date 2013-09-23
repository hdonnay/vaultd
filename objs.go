package main

// vim: set noexpandtab :

import (
	"database/sql"
	"errors"
	"fmt"
	//"io"
	"github.com/gokyle/cryptobox/box"
	"github.com/golang/glog"
	"time"
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
	-- User group means there should only be one member.
	userGroup boolean
);
CREATE TABLE IF NOT EXISTS users_groups (
	uid bigint REFERENCES users (id),
	gid bigint REFERENCES groups (id),
	-- Is user (uid) and admin of group (gid)
	admin bool
);
CREATE TABLE IF NOT EXISTS secrets (
	id     bigserial NOT NULL UNIQUE PRIMARY KEY,
	rev    bigint NOT NULL,
	uri    text,
	note   text,
	box    bytea,
	signer bigint
);
CREATE TABLE IF NOT EXISTS groups_secrets (
	-- All secrets are owned by a group. All users have a group they're the only member of.
	-- This may make some lookups more expensive, but makes lookups logically simpler
	owner  bigint REFERENCES groups (id),
	secret bigint REFERENCES secrets (id)
);
DROP TABLE IF EXISTS session;
CREATE TABLE session (
	id        bigint,
	token     bytea,
	challenge bytea,
	expire    timestamp
);
CREATE OR REPLACE VIEW users_secrets AS
	SELECT u.id AS uid, s.id AS id, s.rev, s.uri, s.note, s.box, s.signer FROM
		users as u
		LEFT JOIN users_groups AS ug ON (u.id = ug.uid)
		LEFT JOIN groups AS g ON (g.id = ug.gid)
		LEFT JOIN groups_secrets AS gs ON (g.id = gs.owner)
		LEFT JOIN secrets AS s ON (s.id = gs.secret)
WHERE s.box IS NOT NULL;
COMMIT; `

func dbInit(db *sql.DB) error {
	var err error
	_, err = db.Exec(initSQL)
	if err != nil {
		glog.Errorln("error intializing database")
		return err
	}
	q = map[string]*sql.Stmt{}
	prepare := map[string]string{
		"getUser":          "SELECT name, pubkey, creation, admin FROM users WHERE id = $1",
		"getUserIdByName":  "SELECT id FROM users WHERE name = $1",
		"getGroup":         "SELECT name, userGroup FROM groups WHERE id = $1",
		"getGroupIdByName": "SELECT id FROM groups WHERE name = $1",
		"checkToken":       "SELECT EXISTS (SELECT 1 FROM session WHERE id = $1 AND token = $2 AND expire > current_timestamp);",
		"checkChallenge":   "SELECT EXISTS (SELECT 1 FROM session WHERE id = $1 AND challenge = $2 AND expire > current_timestamp);",
	}
	for name, query := range prepare {
		x, err := db.Prepare(query)
		if err != nil {
			glog.Errorf("error preparing: %s\t%s\n", name, query)
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
	PubKey   box.PublicKey
	Creation time.Time
	Admin    bool
}

func (u *User) String() string {
	return fmt.Sprintf("%x\t%s", u.Id, u.Name)
}

func (u *User) Save() error {
	var err error
	var id int64

	if u.Id != 0 {
		return errors.New("user Id already populated")
	}

	tx, err := db.Begin()
	var gid int64
	if err != nil {
		return errors.New("unable to begin transaction to create user")
	}
	err = tx.QueryRow("INSERT INTO groups (id, name, userGroup) VALUES (default, $1, TRUE) RETURNING id;", fmt.Sprintf("%s/group", u.Name)).
		Scan(&gid)
	if err != nil {
		tx.Rollback()
		return errors.New(fmt.Sprintf("unable to create group for user: %v", err))
	}
	err = tx.QueryRow("INSERT INTO users (id, name, pubKey, creation, admin) VALUES (default, $1, $2, $3, $4) RETURNING id;",
		u.Name, []byte(u.PubKey), u.Creation, u.Admin).Scan(&id)
	if err != nil {
		tx.Rollback()
		return errors.New(fmt.Sprintf("unable to insert user: %v", err))
	}
	u.Id = id
	_, err = tx.Exec("INSERT INTO users_groups (uid, gid, admin) VALUES ($1, $2, TRUE);", id, gid)
	if err != nil {
		tx.Rollback()
		return errors.New(fmt.Sprintf("unable to associate user and group: %v", err))
	}
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return errors.New(fmt.Sprintf("unable to commit transaction to create user: %v", err))
	}

	if glog.V(1) {
		glog.Infof("User.Save(): Last Insert Id: %x\n", id)
	}
	return nil
}

// Group
type Group struct {
	Id        int64
	Name      string
	Admin     []int64
	Member    []int64
	UserGroup bool
}

func (g *Group) String() string {
	return fmt.Sprintf("%x\t%s", g.Id, g.Name)
}

func (g *Group) Save() error {
	var err error
	var id int64

	if g.Id != 0 {
		return errors.New("group Id already populated")
	}

	err = db.QueryRow("INSERT INTO groups (id, name, userGroup) VALUES (default, $1, $2) RETURNING id;", g.Name, g.UserGroup).
		Scan(&id)
	if err != nil {
		return err
	}

	g.Id = id

	if glog.V(1) {
		glog.Infof("Group.Save(): Last Insert Id: %x\n", id)
	}
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
	Id   int64
	Uri  string
	Note string
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
	return &User{id, name, k, creation, admin}, nil
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
	var primary bool
	err := q["getGroup"].QueryRow(id).Scan(&name, &primary)
	if err != nil {
		return nil, err
	}
	return &Group{Id: id, Name: name, UserGroup: primary}, nil
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

func NewUser(name string, admin bool) (error, *User, box.PrivateKey) {
	var err error
	priv, pub, ok := box.GenerateKey()
	if !ok {
		glog.Errorln(err)
		return err, nil, nil
	}
	// cast so that we don't need to need to include cryptobox everywhere
	newUser := &User{Name: name, PubKey: pub, Creation: time.Now().UTC(), Admin: admin}
	err = newUser.Save()
	if err != nil {
		glog.Errorln(err)
		return err, nil, nil
	}
	return nil, newUser, priv
}

func NewGroup(name string, primaryUserId int64, isUserGroup bool) (error, *Group) {
	var err error
	if err != nil {
		return err, nil
	}
	var newGroup *Group = &Group{Name: name, UserGroup: isUserGroup}
	err = newGroup.Save()
	if err != nil {
		glog.Errorln(err)
		return err, nil
	}
	_, err = db.Exec("INSERT INTO users_groups (uid, gid, admin) VALUES ($1, $2, TRUE);", primaryUserId, newGroup.Id)
	if err != nil {
		glog.Errorln(err)
		return err, nil
	}
	return nil, newGroup
}
