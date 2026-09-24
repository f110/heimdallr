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
	UserState          *UserState
	RoleBinding        *RoleBinding
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
		UserState:          NewUserState(conn),
	}
}
