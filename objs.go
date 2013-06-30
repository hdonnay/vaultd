package main

// vim: set noexpandtab :

import (
	//"code.google.com/p/go.crypto/bcrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"time"
)

const (
	bcryptCost = 12
)

type User struct {
	Id          int64
	Name        string
	PubKey      []byte
	Token       []byte
	TokenExpire time.Time
	Create      time.Time
	Admin       bool
}

func (u *User) String() string {
	return fmt.Sprintf("%x\t%s", u.Id, u.Name)
}

type UserGroupMap struct {
	Id      int64
	UserId  int64
	GroupId int64
	Admin   bool
	PrivKey []byte
}

func (ugm *UserGroupMap) String() string {
	return fmt.Sprintf("%x\t%x\t%x", ugm.Id, ugm.UserId, ugm.GroupId)
}

type Group struct {
	Id     int64
	Name   string
	PubKey []byte
	Hidden bool
}

func (g *Group) String() string {
	return fmt.Sprintf("%x\t%s", g.Id, g.Name)
}

type GroupSecretMap struct {
	Id       int64
	GroupId  int64
	SecretId int64
	SymKey   []byte
}

func (gsm *GroupSecretMap) String() string {
	return fmt.Sprintf("%x\t%x\t%x", gsm.Id, gsm.GroupId, gsm.SecretId)
}

type Secret struct {
	Id         int64
	Uri        string
	Note       string
	Meta       map[string]string
	Ciphertext []byte
}

func (s *Secret) String() string {
	return fmt.Sprintf("%x\t%s", s.Id, s.Uri)
}

type db struct {
	sql.DB
	selUserId    *sql.Stmt
	selGroupId   *sql.Stmt
	insChallenge *sql.Stmt
	insUser      *sql.Stmt
	insGroup     *sql.Stmt
	insUGM       *sql.Stmt
}

func NewDB(conn *sql.DB) (*db, error) {
	selUserId, err := conn.Prepare("SELECT id FROM users WHERE name = $1")
	if err != nil {
		return nil, err
	}
	selGroupId, err := conn.Prepare("SELECT id FROM groups WHERE name = $1")
	if err != nil {
		return nil, err
	}
	insChallenge, err := conn.Prepare("INSERT INTO session (id, challenge, expire) VALUES ($1, $2, $3);")
	if err != nil {
		return nil, err
	}
	insUser, err := conn.Prepare("INSERT INTO users (id, name, pubKey, creation, admin) VALUES (default, $1, $2, $3, $4);")
	if err != nil {
		return nil, err
	}
	insGroup, err := conn.Prepare("INSERT INTO groups (id, name, pubKey, cryptedPrivKey, hidden) VALUES (default, $1, $2, $3, $4);")
	if err != nil {
		return nil, err
	}
	insUGM, err := conn.Prepare("INSERT INTO ugm (id, userId, groupId, cryptedSymKey, admin) VALUES (default, $1, $2, $3, $4)")
	if err != nil {
		return nil, err
	}
	return &db{
		*conn,
		selUserId,
		selGroupId,
		insChallenge,
		insUser,
		insGroup,
		insUGM,
	}, nil
}

func (db *db) NewUser(name string) (int64, *rsa.PrivateKey, error) {
	l.Printf("Making user '%s'\n", name)
	userPriv, err := rsa.GenerateKey(rand.Reader, userKeySize)
	if err != nil {
		l.Println(err)
		return 0, nil, err
	}

	userPubKey, err := x509.MarshalPKIXPublicKey(&userPriv.PublicKey)
	if err != nil {
		l.Println(err)
		return 0, nil, err
	}

	//store
	_, err = db.insUser.Exec(name, userPubKey, time.Now(), true)
	if err != nil {
		l.Println("insUser", err)
		return 0, nil, err
	}
	var id int64
	err = db.selUserId.QueryRow(name).Scan(&id)
	if err != nil {
		l.Println("res", err)
		return 0, nil, err
	}
	l.Printf("Made user '%s' with id %d\n", name, id)

	return id, userPriv, nil
}

func (db *db) NewGroup(name string, primary int64) (int64, error) {
	l.Printf("Making group '%s'\n", name)
	groupPriv, err := rsa.GenerateKey(rand.Reader, groupKeySize)
	if err != nil {
		l.Println(err)
		return 0, err
	}
	groupPubKey, err := x509.MarshalPKIXPublicKey(&groupPriv.PublicKey)
	if err != nil {
		l.Println(err)
		return 0, err
	}

	// make the symmetric key
	ugmKey := make([]byte, 32) //AES-256
	_, err = io.ReadFull(rand.Reader, ugmKey)
	if err != nil {
		l.Println(err)
		return 0, err
	}

	// do aes
	block, err := aes.NewCipher(ugmKey)
	if err != nil {
		l.Println(err)
		return 0, err
	}
	marshaledPrivKey := x509.MarshalPKCS1PrivateKey(groupPriv)
	ciphertext := make([]byte, aes.BlockSize+len(marshaledPrivKey))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		l.Println(err)
		return 0, err
	}

	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(ciphertext[aes.BlockSize:], marshaledPrivKey)

	_, err = db.insGroup.Exec(name, groupPubKey, ciphertext, true)
	if err != nil {
		l.Println(err)
		return 0, err
	}
	var userKeyder []byte
	err = db.QueryRow("SELECT PubKey FROM users WHERE id = $1", primary).Scan(&userKeyder)
	if err != nil {
		l.Println(err)
		return 0, err
	}
	userKey, _ := x509.ParsePKIXPublicKey(userKeyder)
	cryptedSymKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, userKey.(*rsa.PublicKey), ugmKey, []byte(name))
	if err != nil {
		l.Println(err)
		return 0, err
	}
	_, err = db.insUGM.Exec(1, 1, cryptedSymKey, true)
	if err != nil {
		l.Println(err)
		return 0, err
	}
	var id int64
	err = db.selGroupId.QueryRow(name).Scan(&id)
	if err != nil {
		return 0, err
	}
	l.Printf("Made group '%s' with id %d\n", name, id)
	return id, nil
}
