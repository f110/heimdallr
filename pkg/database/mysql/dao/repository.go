package dao

import (
	"database/sql"
)

type Repository struct {
	Conn               *sql.DB
	SerialNumber       *SerialNumber
	SignedCertificate  *SignedCertificate
	RevokedCertificate *RevokedCertificate
	Node               *Node
	Relay              *Relay
	Token              *Token
	Code               *Code
	User               *User
	RoleBinding        *RoleBinding
	AccessToken        *AccessToken
	UserState          *UserState
}

func NewRepository(conn *sql.DB) *Repository {
	return &Repository{
		Conn:               conn,
		SerialNumber:       NewSerialNumber(conn),
		SignedCertificate:  NewSignedCertificate(conn),
		RevokedCertificate: NewRevokedCertificate(conn),
		Node:               NewNode(conn),
		Relay:              NewRelay(conn),
		Token:              NewToken(conn),
		Code:               NewCode(conn),
		User:               NewUser(conn),
		RoleBinding:        NewRoleBinding(conn),
		AccessToken:        NewAccessToken(conn),
		UserState:          NewUserState(conn),
	}
}
