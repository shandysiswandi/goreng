// Code generated by mockery. DO NOT EDIT.

package mocker

import (
	context "context"

	messaging "github.com/shandysiswandi/goreng/messaging"
	mock "github.com/stretchr/testify/mock"
)

// MockMessagingClient is an autogenerated mock type for the Client type
type MockMessagingClient struct {
	mock.Mock
}

type MockMessagingClient_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMessagingClient) EXPECT() *MockMessagingClient_Expecter {
	return &MockMessagingClient_Expecter{mock: &_m.Mock}
}

// BulkPublish provides a mock function with given fields: ctx, topic, data
func (_m *MockMessagingClient) BulkPublish(ctx context.Context, topic string, data []*messaging.Data) error {
	ret := _m.Called(ctx, topic, data)

	if len(ret) == 0 {
		panic("no return value specified for BulkPublish")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []*messaging.Data) error); ok {
		r0 = rf(ctx, topic, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockMessagingClient_BulkPublish_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BulkPublish'
type MockMessagingClient_BulkPublish_Call struct {
	*mock.Call
}

// BulkPublish is a helper method to define mock.On call
//   - ctx context.Context
//   - topic string
//   - data []*messaging.Data
func (_e *MockMessagingClient_Expecter) BulkPublish(ctx interface{}, topic interface{}, data interface{}) *MockMessagingClient_BulkPublish_Call {
	return &MockMessagingClient_BulkPublish_Call{Call: _e.mock.On("BulkPublish", ctx, topic, data)}
}

func (_c *MockMessagingClient_BulkPublish_Call) Run(run func(ctx context.Context, topic string, data []*messaging.Data)) *MockMessagingClient_BulkPublish_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].([]*messaging.Data))
	})
	return _c
}

func (_c *MockMessagingClient_BulkPublish_Call) Return(_a0 error) *MockMessagingClient_BulkPublish_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessagingClient_BulkPublish_Call) RunAndReturn(run func(context.Context, string, []*messaging.Data) error) *MockMessagingClient_BulkPublish_Call {
	_c.Call.Return(run)
	return _c
}

// Close provides a mock function with no fields
func (_m *MockMessagingClient) Close() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Close")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockMessagingClient_Close_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Close'
type MockMessagingClient_Close_Call struct {
	*mock.Call
}

// Close is a helper method to define mock.On call
func (_e *MockMessagingClient_Expecter) Close() *MockMessagingClient_Close_Call {
	return &MockMessagingClient_Close_Call{Call: _e.mock.On("Close")}
}

func (_c *MockMessagingClient_Close_Call) Run(run func()) *MockMessagingClient_Close_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessagingClient_Close_Call) Return(_a0 error) *MockMessagingClient_Close_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessagingClient_Close_Call) RunAndReturn(run func() error) *MockMessagingClient_Close_Call {
	_c.Call.Return(run)
	return _c
}

// Publish provides a mock function with given fields: ctx, topic, data
func (_m *MockMessagingClient) Publish(ctx context.Context, topic string, data *messaging.Data) error {
	ret := _m.Called(ctx, topic, data)

	if len(ret) == 0 {
		panic("no return value specified for Publish")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *messaging.Data) error); ok {
		r0 = rf(ctx, topic, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockMessagingClient_Publish_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Publish'
type MockMessagingClient_Publish_Call struct {
	*mock.Call
}

// Publish is a helper method to define mock.On call
//   - ctx context.Context
//   - topic string
//   - data *messaging.Data
func (_e *MockMessagingClient_Expecter) Publish(ctx interface{}, topic interface{}, data interface{}) *MockMessagingClient_Publish_Call {
	return &MockMessagingClient_Publish_Call{Call: _e.mock.On("Publish", ctx, topic, data)}
}

func (_c *MockMessagingClient_Publish_Call) Run(run func(ctx context.Context, topic string, data *messaging.Data)) *MockMessagingClient_Publish_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(*messaging.Data))
	})
	return _c
}

func (_c *MockMessagingClient_Publish_Call) Return(_a0 error) *MockMessagingClient_Publish_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessagingClient_Publish_Call) RunAndReturn(run func(context.Context, string, *messaging.Data) error) *MockMessagingClient_Publish_Call {
	_c.Call.Return(run)
	return _c
}

// Subscribe provides a mock function with given fields: ctx, topic, subscriptionID, handler
func (_m *MockMessagingClient) Subscribe(ctx context.Context, topic string, subscriptionID string, handler messaging.SubscriberFunc) error {
	ret := _m.Called(ctx, topic, subscriptionID, handler)

	if len(ret) == 0 {
		panic("no return value specified for Subscribe")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, messaging.SubscriberFunc) error); ok {
		r0 = rf(ctx, topic, subscriptionID, handler)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockMessagingClient_Subscribe_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Subscribe'
type MockMessagingClient_Subscribe_Call struct {
	*mock.Call
}

// Subscribe is a helper method to define mock.On call
//   - ctx context.Context
//   - topic string
//   - subscriptionID string
//   - handler messaging.SubscriberFunc
func (_e *MockMessagingClient_Expecter) Subscribe(ctx interface{}, topic interface{}, subscriptionID interface{}, handler interface{}) *MockMessagingClient_Subscribe_Call {
	return &MockMessagingClient_Subscribe_Call{Call: _e.mock.On("Subscribe", ctx, topic, subscriptionID, handler)}
}

func (_c *MockMessagingClient_Subscribe_Call) Run(run func(ctx context.Context, topic string, subscriptionID string, handler messaging.SubscriberFunc)) *MockMessagingClient_Subscribe_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(messaging.SubscriberFunc))
	})
	return _c
}

func (_c *MockMessagingClient_Subscribe_Call) Return(_a0 error) *MockMessagingClient_Subscribe_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessagingClient_Subscribe_Call) RunAndReturn(run func(context.Context, string, string, messaging.SubscriberFunc) error) *MockMessagingClient_Subscribe_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMessagingClient creates a new instance of MockMessagingClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMessagingClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMessagingClient {
	mock := &MockMessagingClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
