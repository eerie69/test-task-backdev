package helper

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"
    "test-task-backdev/models"
	"test-task-backdev/database"
	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type SignedDetails struct{
	Refresh_token  []byte
	Uid 		string
	jwt.StandardClaims 
}


var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = os.Getenv("SECRET_KEY")

func GenerateAllTokens(uid string) (signedToken string, signedRefreshToken []byte, err error){
	claims := &SignedDetails{
		Refresh_token: signedRefreshToken,
		Uid : uid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	token ,err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString([]byte(SECRET_KEY))
    if err != nil {
		log.Panic(err)
		return 
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(err)
	}

	refreshToken, err := bcrypt.GenerateFromPassword(randomBytes, bcrypt.DefaultCost)
	if err != nil {
		log.Panic(err)
		return 
	}

	return token, refreshToken, err
}


func ValidateToken(signedToken string) (claims *SignedDetails, msg string){
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token)(interface{}, error){
			return []byte(SECRET_KEY), nil
		},
	)
	
	if err != nil {
		msg=err.Error()
		return
	}

	var rfTokenHash models.TokenClaims
    var rfToken models.TokensPair

	claims, ok:= token.Claims.(*SignedDetails)
	if !ok{
		msg = fmt.Sprintf("the token is invalid")
		msg = err.Error()
		return
	}else if bcrypt.CompareHashAndPassword(rfTokenHash.Refresh_token, rfToken.Refresh_token) != nil {
		msg = fmt.Sprintf("invalid refresh token")
		msg = err.Error()
		return
	} else if !IsHashExistsInDB(rfTokenHash.Refresh_token) {
        msg = fmt.Sprintf( "no such refresh token in db")
		msg = err.Error()
        return
    }

	if claims.ExpiresAt < time.Now().Local().Unix(){
		msg = fmt.Sprintf("token is expired")
		msg = err.Error()
		return
	}
	return claims, msg
}

func UpdateAllTokens(signedToken string, signedRefreshToken []byte, userId string){
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var updateObj primitive.D

	updateObj = append(updateObj, bson.E{"token", signedToken})

	res := base64.StdEncoding.EncodeToString(signedRefreshToken)
	updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: res})
	
	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{"updated_at", Updated_at})

	upsert := true
	filter := bson.M{"user_id":userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{"$set", updateObj},
		},
		&opt,
	)

	defer cancel()

	if err!=nil{
		log.Panic(err)
		return
	}
	return
}

func IsHashExistsInDB(hash []byte) bool {
	res := base64.StdEncoding.EncodeToString(hash)
	err := userCollection.FindOne(context.TODO(), bson.D{{Key: "refresh_token", Value: res}}).Err()

	if err == mongo.ErrNoDocuments {
		return false
	} else if err != nil {
		panic(err)
	} else {
		return true
	}
}