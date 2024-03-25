package models

import(
	"time"
"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct{
	ID				primitive.ObjectID		`bson:"_id"`
	Refresh_token   []byte                  `json:"refresh_token"`
	Created_at		time.Time				`json:"created_at"`
	Updated_at		time.Time				`json:"updated_at"`
}

type TokenClaims struct {
	Refresh_token   []byte                  `json:"refresh_token"`
	User_id			string					`json:"user_id"`
}

type TokensPair struct {
	Token			*string					`json:"token"`
	Refresh_token   []byte                  `json:"refresh_token"`
}