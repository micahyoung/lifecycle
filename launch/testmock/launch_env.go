// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/buildpacks/lifecycle/launch (interfaces: Env)

// Package testmock is a generated GoMock package.
package testmock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockEnv is a mock of Env interface
type MockEnv struct {
	ctrl     *gomock.Controller
	recorder *MockEnvMockRecorder
}

// MockEnvMockRecorder is the mock recorder for MockEnv
type MockEnvMockRecorder struct {
	mock *MockEnv
}

// NewMockEnv creates a new mock instance
func NewMockEnv(ctrl *gomock.Controller) *MockEnv {
	mock := &MockEnv{ctrl: ctrl}
	mock.recorder = &MockEnvMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockEnv) EXPECT() *MockEnvMockRecorder {
	return m.recorder
}

// AddEnvDir mocks base method
func (m *MockEnv) AddEnvDir(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddEnvDir", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddEnvDir indicates an expected call of AddEnvDir
func (mr *MockEnvMockRecorder) AddEnvDir(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddEnvDir", reflect.TypeOf((*MockEnv)(nil).AddEnvDir), arg0)
}

// AddRootDir mocks base method
func (m *MockEnv) AddRootDir(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRootDir", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRootDir indicates an expected call of AddRootDir
func (mr *MockEnvMockRecorder) AddRootDir(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRootDir", reflect.TypeOf((*MockEnv)(nil).AddRootDir), arg0)
}

// Get mocks base method
func (m *MockEnv) Get(arg0 string) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0)
	ret0, _ := ret[0].(string)
	return ret0
}

// Get indicates an expected call of Get
func (mr *MockEnvMockRecorder) Get(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockEnv)(nil).Get), arg0)
}

// List mocks base method
func (m *MockEnv) List() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List")
	ret0, _ := ret[0].([]string)
	return ret0
}

// List indicates an expected call of List
func (mr *MockEnvMockRecorder) List() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockEnv)(nil).List))
}
