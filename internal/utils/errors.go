package utils

import "fmt"

type CustomError struct {
	Code    int
	Message string
}

func (e *CustomError) Error() string {
	return fmt.Sprintf("Code: %d, Message: %s", e.Code, e.Message)
}

func New(code int, message string) error {
	return &CustomError{
		Code:    code,
		Message: message,
	}
}
