// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: goerror/error.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Error struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type       string            `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	Code       string            `protobuf:"bytes,2,opt,name=code,proto3" json:"code,omitempty"`
	Message    string            `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
	Attributes map[string]string `protobuf:"bytes,4,rep,name=attributes,proto3" json:"attributes,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Error) Reset() {
	*x = Error{}
	if protoimpl.UnsafeEnabled {
		mi := &file_goerror_error_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Error) ProtoMessage() {}

func (x *Error) ProtoReflect() protoreflect.Message {
	mi := &file_goerror_error_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Error.ProtoReflect.Descriptor instead.
func (*Error) Descriptor() ([]byte, []int) {
	return file_goerror_error_proto_rawDescGZIP(), []int{0}
}

func (x *Error) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Error) GetCode() string {
	if x != nil {
		return x.Code
	}
	return ""
}

func (x *Error) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *Error) GetAttributes() map[string]string {
	if x != nil {
		return x.Attributes
	}
	return nil
}

var File_goerror_error_proto protoreflect.FileDescriptor

var file_goerror_error_proto_rawDesc = []byte{
	0x0a, 0x13, 0x67, 0x6f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x67, 0x6f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x72,
	0x22, 0xca, 0x01, 0x0a, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x63, 0x6f,
	0x64, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x40, 0x0a, 0x0a,
	0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x20, 0x2e, 0x67, 0x6f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x72, 0x2e, 0x45, 0x72, 0x72,
	0x6f, 0x72, 0x2e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x1a, 0x3d,
	0x0a, 0x0f, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x90, 0x01,
	0x0a, 0x0d, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x6f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x72, 0x42,
	0x0a, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2f, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x68, 0x61, 0x6e, 0x64, 0x79,
	0x73, 0x69, 0x73, 0x77, 0x61, 0x6e, 0x64, 0x69, 0x2f, 0x67, 0x6f, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x6f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0xa2, 0x02,
	0x03, 0x47, 0x58, 0x58, 0xaa, 0x02, 0x09, 0x47, 0x6f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x72,
	0xca, 0x02, 0x09, 0x47, 0x6f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x72, 0xe2, 0x02, 0x15, 0x47,
	0x6f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x72, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x09, 0x47, 0x6f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x72,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_goerror_error_proto_rawDescOnce sync.Once
	file_goerror_error_proto_rawDescData = file_goerror_error_proto_rawDesc
)

func file_goerror_error_proto_rawDescGZIP() []byte {
	file_goerror_error_proto_rawDescOnce.Do(func() {
		file_goerror_error_proto_rawDescData = protoimpl.X.CompressGZIP(file_goerror_error_proto_rawDescData)
	})
	return file_goerror_error_proto_rawDescData
}

var file_goerror_error_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_goerror_error_proto_goTypes = []any{
	(*Error)(nil), // 0: gostarter.Error
	nil,           // 1: gostarter.Error.AttributesEntry
}
var file_goerror_error_proto_depIdxs = []int32{
	1, // 0: gostarter.Error.attributes:type_name -> gostarter.Error.AttributesEntry
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_goerror_error_proto_init() }
func file_goerror_error_proto_init() {
	if File_goerror_error_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_goerror_error_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Error); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_goerror_error_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_goerror_error_proto_goTypes,
		DependencyIndexes: file_goerror_error_proto_depIdxs,
		MessageInfos:      file_goerror_error_proto_msgTypes,
	}.Build()
	File_goerror_error_proto = out.File
	file_goerror_error_proto_rawDesc = nil
	file_goerror_error_proto_goTypes = nil
	file_goerror_error_proto_depIdxs = nil
}
