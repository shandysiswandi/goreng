// Code generated by mockery. DO NOT EDIT.

package mocker

import (
	time "time"

	mock "github.com/stretchr/testify/mock"
)

// MockClocker is an autogenerated mock type for the Clocker type
type MockClocker struct {
	mock.Mock
}

type MockClocker_Expecter struct {
	mock *mock.Mock
}

func (_m *MockClocker) EXPECT() *MockClocker_Expecter {
	return &MockClocker_Expecter{mock: &_m.Mock}
}

// Now provides a mock function with no fields
func (_m *MockClocker) Now() time.Time {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Now")
	}

	var r0 time.Time
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	return r0
}

// MockClocker_Now_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Now'
type MockClocker_Now_Call struct {
	*mock.Call
}

// Now is a helper method to define mock.On call
func (_e *MockClocker_Expecter) Now() *MockClocker_Now_Call {
	return &MockClocker_Now_Call{Call: _e.mock.On("Now")}
}

func (_c *MockClocker_Now_Call) Run(run func()) *MockClocker_Now_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockClocker_Now_Call) Return(_a0 time.Time) *MockClocker_Now_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClocker_Now_Call) RunAndReturn(run func() time.Time) *MockClocker_Now_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockClocker creates a new instance of MockClocker. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockClocker(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockClocker {
	mock := &MockClocker{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
