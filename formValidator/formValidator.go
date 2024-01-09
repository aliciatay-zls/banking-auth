package formValidator

import (
	"bufio"
	"github.com/go-playground/validator/v10"
	"os"
	"regexp"
)

const UsernameAlias = "un"

var appValidator *validator.Validate
var codeCountryMap map[string]string

func Create() {
	appValidator = validator.New(validator.WithRequiredStructEnabled())
	useCustomUsernameValidator()
	createCodeCountryMap()
}

func useCustomUsernameValidator() {
	unRegex := regexp.MustCompile("^[A-Za-z]\\w{5,19}$")

	if err := appValidator.RegisterValidation("validusername", func(fl validator.FieldLevel) bool {
		return unRegex.MatchString(fl.Field().String())
	}); err != nil {
		panic(err)
	}

	appValidator.RegisterAlias(UsernameAlias, "required,min=6,max=20,validusername")
}

func createCodeCountryMap() {
	codeCountryMap = map[string]string{}

	f1, err := os.Open("./formValidator/codes.txt")
	if err != nil {
		panic(err)
	}
	defer f1.Close()

	f2, err := os.Open("./formValidator/countries.txt")
	if err != nil {
		panic(err)
	}
	defer f2.Close()

	s1 := bufio.NewScanner(f1)
	s2 := bufio.NewScanner(f2)
	for s1.Scan() {
		s2.Scan()
		codeCountryMap[s1.Text()] = s2.Text()
	}
}

func GetCountryFrom(code string) string {
	return codeCountryMap[code]
}

// Wrapped functions from go-playground/validator

func Struct(s interface{}) error {
	return appValidator.Struct(s)
}
