// Code generated by mockery v2.30.1. DO NOT EDIT.

package mocks

import (
	jwt "github.com/golang-jwt/jwt"

	mock "github.com/stretchr/testify/mock"
)

// ProfileService is an autogenerated mock type for the ProfileService type
type ProfileService struct {
	mock.Mock
}

// ExtractTokenFromAuthHeader provides a mock function with given fields: authHeaderString
func (_m *ProfileService) ExtractTokenFromAuthHeader(authHeaderString string) (string, error) {
	ret := _m.Called(authHeaderString)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(authHeaderString)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(authHeaderString)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(authHeaderString)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateToken provides a mock function with given fields: tokenString
func (_m *ProfileService) ValidateToken(tokenString string) (*jwt.Token, error) {
	ret := _m.Called(tokenString)

	var r0 *jwt.Token
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*jwt.Token, error)); ok {
		return rf(tokenString)
	}
	if rf, ok := ret.Get(0).(func(string) *jwt.Token); ok {
		r0 = rf(tokenString)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*jwt.Token)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(tokenString)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewProfileService creates a new instance of ProfileService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewProfileService(t interface {
	mock.TestingT
	Cleanup(func())
}) *ProfileService {
	mock := &ProfileService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
