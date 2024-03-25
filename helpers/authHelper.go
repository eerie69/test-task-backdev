package helper

import(
	"errors"
	"github.com/gin-gonic/gin"
)



func MatchToUid(c *gin.Context, userId string) (err error){
	uid := c.GetString("uid")
	err = nil

	if uid != userId {
		err = errors.New("Unauthorized to access this resource")
		return err
	}
	return err
}