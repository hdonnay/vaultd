package main

// vim: set noexpandtab :

import (
	//"code.google.com/p/go.crypto/bcrypt"
	"fmt"
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
