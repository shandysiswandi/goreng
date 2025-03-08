// Code generated by mockery. DO NOT EDIT.

package mocker

import mock "github.com/stretchr/testify/mock"

// MockHash is an autogenerated mock type for the Hash type
type MockHash struct {
	mock.Mock
}

type MockHash_Expecter struct {
	mock *mock.Mock
}

func (_m *MockHash) EXPECT() *MockHash_Expecter {
	return &MockHash_Expecter{mock: &_m.Mock}
}

// Hash provides a mock function with given fields: str
func (_m *MockHash) Hash(str string) ([]byte, error) {
	ret := _m.Called(str)

	if len(ret) == 0 {
		panic("no return value specified for Hash")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]byte, error)); ok {
		return rf(str)
	}
	if rf, ok := ret.Get(0).(func(string) []byte); ok {
		r0 = rf(str)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(str)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockHash_Hash_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Hash'
type MockHash_Hash_Call struct {
	*mock.Call
}

// Hash is a helper method to define mock.On call
//   - str string
func (_e *MockHash_Expecter) Hash(str interface{}) *MockHash_Hash_Call {
	return &MockHash_Hash_Call{Call: _e.mock.On("Hash", str)}
}

func (_c *MockHash_Hash_Call) Run(run func(str string)) *MockHash_Hash_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockHash_Hash_Call) Return(_a0 []byte, _a1 error) *MockHash_Hash_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockHash_Hash_Call) RunAndReturn(run func(string) ([]byte, error)) *MockHash_Hash_Call {
	_c.Call.Return(run)
	return _c
}

// Verify provides a mock function with given fields: hashed, str
func (_m *MockHash) Verify(hashed string, str string) bool {
	ret := _m.Called(hashed, str)

	if len(ret) == 0 {
		panic("no return value specified for Verify")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(string, string) bool); ok {
		r0 = rf(hashed, str)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// MockHash_Verify_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Verify'
type MockHash_Verify_Call struct {
	*mock.Call
}

// Verify is a helper method to define mock.On call
//   - hashed string
//   - str string
func (_e *MockHash_Expecter) Verify(hashed interface{}, str interface{}) *MockHash_Verify_Call {
	return &MockHash_Verify_Call{Call: _e.mock.On("Verify", hashed, str)}
}

func (_c *MockHash_Verify_Call) Run(run func(hashed string, str string)) *MockHash_Verify_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *MockHash_Verify_Call) Return(_a0 bool) *MockHash_Verify_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHash_Verify_Call) RunAndReturn(run func(string, string) bool) *MockHash_Verify_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockHash creates a new instance of MockHash. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockHash(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockHash {
	mock := &MockHash{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
