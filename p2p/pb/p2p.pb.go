// Code generated by protoc-gen-go. DO NOT EDIT.
// source: p2p.proto

package pb

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// designed to be shared between all app protocols
type MessageData struct {
	// shared between all requests
	ClientVersion        string   `protobuf:"bytes,1,opt,name=clientVersion,proto3" json:"clientVersion,omitempty"`
	Timestamp            int64    `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Id                   string   `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"`
	Gossip               bool     `protobuf:"varint,4,opt,name=gossip,proto3" json:"gossip,omitempty"`
	NodeId               string   `protobuf:"bytes,5,opt,name=nodeId,proto3" json:"nodeId,omitempty"`
	NodePubKey           []byte   `protobuf:"bytes,6,opt,name=nodePubKey,proto3" json:"nodePubKey,omitempty"`
	Sign                 []byte   `protobuf:"bytes,7,opt,name=sign,proto3" json:"sign,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MessageData) Reset()         { *m = MessageData{} }
func (m *MessageData) String() string { return proto.CompactTextString(m) }
func (*MessageData) ProtoMessage()    {}
func (*MessageData) Descriptor() ([]byte, []int) {
	return fileDescriptor_e7fdddb109e6467a, []int{0}
}

func (m *MessageData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MessageData.Unmarshal(m, b)
}
func (m *MessageData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MessageData.Marshal(b, m, deterministic)
}
func (m *MessageData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MessageData.Merge(m, src)
}
func (m *MessageData) XXX_Size() int {
	return xxx_messageInfo_MessageData.Size(m)
}
func (m *MessageData) XXX_DiscardUnknown() {
	xxx_messageInfo_MessageData.DiscardUnknown(m)
}

var xxx_messageInfo_MessageData proto.InternalMessageInfo

func (m *MessageData) GetClientVersion() string {
	if m != nil {
		return m.ClientVersion
	}
	return ""
}

func (m *MessageData) GetTimestamp() int64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *MessageData) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *MessageData) GetGossip() bool {
	if m != nil {
		return m.Gossip
	}
	return false
}

func (m *MessageData) GetNodeId() string {
	if m != nil {
		return m.NodeId
	}
	return ""
}

func (m *MessageData) GetNodePubKey() []byte {
	if m != nil {
		return m.NodePubKey
	}
	return nil
}

func (m *MessageData) GetSign() []byte {
	if m != nil {
		return m.Sign
	}
	return nil
}

type UploadQueryRequest struct {
	MessageData          *MessageData `protobuf:"bytes,1,opt,name=messageData,proto3" json:"messageData,omitempty"`
	Path                 string       `protobuf:"bytes,2,opt,name=path,proto3" json:"path,omitempty"`
	Name                 string       `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	Size                 int64        `protobuf:"varint,4,opt,name=size,proto3" json:"size,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *UploadQueryRequest) Reset()         { *m = UploadQueryRequest{} }
func (m *UploadQueryRequest) String() string { return proto.CompactTextString(m) }
func (*UploadQueryRequest) ProtoMessage()    {}
func (*UploadQueryRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e7fdddb109e6467a, []int{1}
}

func (m *UploadQueryRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UploadQueryRequest.Unmarshal(m, b)
}
func (m *UploadQueryRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UploadQueryRequest.Marshal(b, m, deterministic)
}
func (m *UploadQueryRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UploadQueryRequest.Merge(m, src)
}
func (m *UploadQueryRequest) XXX_Size() int {
	return xxx_messageInfo_UploadQueryRequest.Size(m)
}
func (m *UploadQueryRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_UploadQueryRequest.DiscardUnknown(m)
}

var xxx_messageInfo_UploadQueryRequest proto.InternalMessageInfo

func (m *UploadQueryRequest) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *UploadQueryRequest) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *UploadQueryRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *UploadQueryRequest) GetSize() int64 {
	if m != nil {
		return m.Size
	}
	return 0
}

type UploadQueryResponse struct {
	MessageData          *MessageData `protobuf:"bytes,1,opt,name=messageData,proto3" json:"messageData,omitempty"`
	Tag                  string       `protobuf:"bytes,2,opt,name=tag,proto3" json:"tag,omitempty"`
	Size                 int64        `protobuf:"varint,3,opt,name=size,proto3" json:"size,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *UploadQueryResponse) Reset()         { *m = UploadQueryResponse{} }
func (m *UploadQueryResponse) String() string { return proto.CompactTextString(m) }
func (*UploadQueryResponse) ProtoMessage()    {}
func (*UploadQueryResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_e7fdddb109e6467a, []int{2}
}

func (m *UploadQueryResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UploadQueryResponse.Unmarshal(m, b)
}
func (m *UploadQueryResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UploadQueryResponse.Marshal(b, m, deterministic)
}
func (m *UploadQueryResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UploadQueryResponse.Merge(m, src)
}
func (m *UploadQueryResponse) XXX_Size() int {
	return xxx_messageInfo_UploadQueryResponse.Size(m)
}
func (m *UploadQueryResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_UploadQueryResponse.DiscardUnknown(m)
}

var xxx_messageInfo_UploadQueryResponse proto.InternalMessageInfo

func (m *UploadQueryResponse) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *UploadQueryResponse) GetTag() string {
	if m != nil {
		return m.Tag
	}
	return ""
}

func (m *UploadQueryResponse) GetSize() int64 {
	if m != nil {
		return m.Size
	}
	return 0
}

type UploadRequest struct {
	MessageData          *MessageData `protobuf:"bytes,1,opt,name=messageData,proto3" json:"messageData,omitempty"`
	Tag                  string       `protobuf:"bytes,2,opt,name=tag,proto3" json:"tag,omitempty"`
	Id                   int64        `protobuf:"varint,3,opt,name=id,proto3" json:"id,omitempty"`
	Data                 []byte       `protobuf:"bytes,4,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *UploadRequest) Reset()         { *m = UploadRequest{} }
func (m *UploadRequest) String() string { return proto.CompactTextString(m) }
func (*UploadRequest) ProtoMessage()    {}
func (*UploadRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e7fdddb109e6467a, []int{3}
}

func (m *UploadRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UploadRequest.Unmarshal(m, b)
}
func (m *UploadRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UploadRequest.Marshal(b, m, deterministic)
}
func (m *UploadRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UploadRequest.Merge(m, src)
}
func (m *UploadRequest) XXX_Size() int {
	return xxx_messageInfo_UploadRequest.Size(m)
}
func (m *UploadRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_UploadRequest.DiscardUnknown(m)
}

var xxx_messageInfo_UploadRequest proto.InternalMessageInfo

func (m *UploadRequest) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *UploadRequest) GetTag() string {
	if m != nil {
		return m.Tag
	}
	return ""
}

func (m *UploadRequest) GetId() int64 {
	if m != nil {
		return m.Id
	}
	return 0
}

func (m *UploadRequest) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type UploadResponse struct {
	MessageData          *MessageData `protobuf:"bytes,1,opt,name=messageData,proto3" json:"messageData,omitempty"`
	Tag                  string       `protobuf:"bytes,2,opt,name=tag,proto3" json:"tag,omitempty"`
	Id                   int64        `protobuf:"varint,3,opt,name=id,proto3" json:"id,omitempty"`
	Hash                 string       `protobuf:"bytes,4,opt,name=hash,proto3" json:"hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *UploadResponse) Reset()         { *m = UploadResponse{} }
func (m *UploadResponse) String() string { return proto.CompactTextString(m) }
func (*UploadResponse) ProtoMessage()    {}
func (*UploadResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_e7fdddb109e6467a, []int{4}
}

func (m *UploadResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UploadResponse.Unmarshal(m, b)
}
func (m *UploadResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UploadResponse.Marshal(b, m, deterministic)
}
func (m *UploadResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UploadResponse.Merge(m, src)
}
func (m *UploadResponse) XXX_Size() int {
	return xxx_messageInfo_UploadResponse.Size(m)
}
func (m *UploadResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_UploadResponse.DiscardUnknown(m)
}

var xxx_messageInfo_UploadResponse proto.InternalMessageInfo

func (m *UploadResponse) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *UploadResponse) GetTag() string {
	if m != nil {
		return m.Tag
	}
	return ""
}

func (m *UploadResponse) GetId() int64 {
	if m != nil {
		return m.Id
	}
	return 0
}

func (m *UploadResponse) GetHash() string {
	if m != nil {
		return m.Hash
	}
	return ""
}

type OperationRequest struct {
	MessageData          *MessageData `protobuf:"bytes,1,opt,name=messageData,proto3" json:"messageData,omitempty"`
	Tag                  string       `protobuf:"bytes,2,opt,name=tag,proto3" json:"tag,omitempty"`
	Operation            []byte       `protobuf:"bytes,3,opt,name=operation,proto3" json:"operation,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *OperationRequest) Reset()         { *m = OperationRequest{} }
func (m *OperationRequest) String() string { return proto.CompactTextString(m) }
func (*OperationRequest) ProtoMessage()    {}
func (*OperationRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e7fdddb109e6467a, []int{5}
}

func (m *OperationRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OperationRequest.Unmarshal(m, b)
}
func (m *OperationRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OperationRequest.Marshal(b, m, deterministic)
}
func (m *OperationRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OperationRequest.Merge(m, src)
}
func (m *OperationRequest) XXX_Size() int {
	return xxx_messageInfo_OperationRequest.Size(m)
}
func (m *OperationRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_OperationRequest.DiscardUnknown(m)
}

var xxx_messageInfo_OperationRequest proto.InternalMessageInfo

func (m *OperationRequest) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *OperationRequest) GetTag() string {
	if m != nil {
		return m.Tag
	}
	return ""
}

func (m *OperationRequest) GetOperation() []byte {
	if m != nil {
		return m.Operation
	}
	return nil
}

type DownloadRequest struct {
	MessageData          *MessageData `protobuf:"bytes,1,opt,name=messageData,proto3" json:"messageData,omitempty"`
	Hash                 string       `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *DownloadRequest) Reset()         { *m = DownloadRequest{} }
func (m *DownloadRequest) String() string { return proto.CompactTextString(m) }
func (*DownloadRequest) ProtoMessage()    {}
func (*DownloadRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e7fdddb109e6467a, []int{6}
}

func (m *DownloadRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DownloadRequest.Unmarshal(m, b)
}
func (m *DownloadRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DownloadRequest.Marshal(b, m, deterministic)
}
func (m *DownloadRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DownloadRequest.Merge(m, src)
}
func (m *DownloadRequest) XXX_Size() int {
	return xxx_messageInfo_DownloadRequest.Size(m)
}
func (m *DownloadRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_DownloadRequest.DiscardUnknown(m)
}

var xxx_messageInfo_DownloadRequest proto.InternalMessageInfo

func (m *DownloadRequest) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *DownloadRequest) GetHash() string {
	if m != nil {
		return m.Hash
	}
	return ""
}

type DownloadResponse struct {
	MessageData          *MessageData `protobuf:"bytes,1,opt,name=messageData,proto3" json:"messageData,omitempty"`
	Hash                 string       `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
	Data                 []byte       `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *DownloadResponse) Reset()         { *m = DownloadResponse{} }
func (m *DownloadResponse) String() string { return proto.CompactTextString(m) }
func (*DownloadResponse) ProtoMessage()    {}
func (*DownloadResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_e7fdddb109e6467a, []int{7}
}

func (m *DownloadResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DownloadResponse.Unmarshal(m, b)
}
func (m *DownloadResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DownloadResponse.Marshal(b, m, deterministic)
}
func (m *DownloadResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DownloadResponse.Merge(m, src)
}
func (m *DownloadResponse) XXX_Size() int {
	return xxx_messageInfo_DownloadResponse.Size(m)
}
func (m *DownloadResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_DownloadResponse.DiscardUnknown(m)
}

var xxx_messageInfo_DownloadResponse proto.InternalMessageInfo

func (m *DownloadResponse) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *DownloadResponse) GetHash() string {
	if m != nil {
		return m.Hash
	}
	return ""
}

func (m *DownloadResponse) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func init() {
	proto.RegisterType((*MessageData)(nil), "pb.MessageData")
	proto.RegisterType((*UploadQueryRequest)(nil), "pb.UploadQueryRequest")
	proto.RegisterType((*UploadQueryResponse)(nil), "pb.UploadQueryResponse")
	proto.RegisterType((*UploadRequest)(nil), "pb.UploadRequest")
	proto.RegisterType((*UploadResponse)(nil), "pb.UploadResponse")
	proto.RegisterType((*OperationRequest)(nil), "pb.OperationRequest")
	proto.RegisterType((*DownloadRequest)(nil), "pb.DownloadRequest")
	proto.RegisterType((*DownloadResponse)(nil), "pb.DownloadResponse")
}

func init() { proto.RegisterFile("p2p.proto", fileDescriptor_e7fdddb109e6467a) }

var fileDescriptor_e7fdddb109e6467a = []byte{
	// 376 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x93, 0xcf, 0x6a, 0xe3, 0x30,
	0x10, 0xc6, 0xf1, 0x9f, 0xcd, 0xae, 0x27, 0x7f, 0xd1, 0xc2, 0xe2, 0x43, 0x58, 0x8c, 0xe9, 0xc1,
	0xa7, 0x40, 0xd3, 0x57, 0xc8, 0xa5, 0x94, 0xd2, 0x56, 0xd0, 0xd2, 0xab, 0x5c, 0x0b, 0x47, 0x10,
	0x4b, 0xaa, 0x25, 0xd3, 0xa6, 0xd7, 0x3e, 0x5b, 0xdf, 0xab, 0x78, 0xe2, 0xc4, 0x0e, 0xcd, 0x29,
	0xc9, 0xed, 0xd3, 0x67, 0x79, 0xbe, 0xf9, 0xcd, 0x20, 0x08, 0xf4, 0x5c, 0xcf, 0x74, 0xa9, 0xac,
	0x22, 0xae, 0x4e, 0xe3, 0x2f, 0x07, 0xfa, 0xb7, 0xdc, 0x18, 0x96, 0xf3, 0x05, 0xb3, 0x8c, 0x5c,
	0xc0, 0xf0, 0x65, 0x25, 0xb8, 0xb4, 0x4f, 0xbc, 0x34, 0x42, 0xc9, 0xd0, 0x89, 0x9c, 0x24, 0xa0,
	0xfb, 0x26, 0x99, 0x42, 0x60, 0x45, 0xc1, 0x8d, 0x65, 0x85, 0x0e, 0xdd, 0xc8, 0x49, 0x3c, 0xda,
	0x1a, 0x64, 0x04, 0xae, 0xc8, 0x42, 0x0f, 0x7f, 0x74, 0x45, 0x46, 0xfe, 0x41, 0x2f, 0x57, 0xc6,
	0x08, 0x1d, 0xfa, 0x91, 0x93, 0xfc, 0xa1, 0xcd, 0xa9, 0xf6, 0xa5, 0xca, 0xf8, 0x75, 0x16, 0xfe,
	0xc2, 0xbb, 0xcd, 0x89, 0xfc, 0x07, 0xa8, 0xd5, 0x7d, 0x95, 0xde, 0xf0, 0x75, 0xd8, 0x8b, 0x9c,
	0x64, 0x40, 0x3b, 0x0e, 0x21, 0xe0, 0x1b, 0x91, 0xcb, 0xf0, 0x37, 0x7e, 0x41, 0x1d, 0x7f, 0x3a,
	0x40, 0x1e, 0xf5, 0x4a, 0xb1, 0xec, 0xa1, 0xe2, 0xe5, 0x9a, 0xf2, 0xd7, 0x8a, 0x1b, 0x4b, 0x2e,
	0xa1, 0x5f, 0xb4, 0x74, 0x08, 0xd3, 0x9f, 0x8f, 0x67, 0x3a, 0x9d, 0x75, 0xa0, 0x69, 0xf7, 0x4e,
	0x5d, 0x5d, 0x33, 0xbb, 0x44, 0xac, 0x80, 0xa2, 0xae, 0x3d, 0xc9, 0x0a, 0xde, 0x30, 0xa1, 0xde,
	0x74, 0xf1, 0xc1, 0x91, 0xc9, 0xa3, 0xa8, 0x63, 0x09, 0x7f, 0xf7, 0x9a, 0x30, 0x5a, 0x49, 0xc3,
	0x8f, 0xe9, 0x62, 0x02, 0x9e, 0x65, 0x79, 0xd3, 0x44, 0x2d, 0x77, 0x79, 0x5e, 0x27, 0xef, 0x1d,
	0x86, 0x9b, 0xbc, 0x13, 0x78, 0x7f, 0x26, 0xb5, 0xfb, 0xf3, 0x70, 0x7f, 0x04, 0xfc, 0xac, 0xae,
	0xe6, 0x6f, 0xe6, 0x5d, 0xeb, 0x78, 0x0d, 0xa3, 0x6d, 0xf2, 0x39, 0x21, 0x0f, 0x44, 0x2f, 0x99,
	0x59, 0x62, 0x74, 0x40, 0x51, 0xc7, 0x15, 0x4c, 0xee, 0x34, 0x2f, 0x99, 0x15, 0x4a, 0x9e, 0x95,
	0x7b, 0x0a, 0x81, 0xda, 0x16, 0xc6, 0x1e, 0x06, 0xb4, 0x35, 0xe2, 0x67, 0x18, 0x2f, 0xd4, 0x9b,
	0x3c, 0x71, 0xda, 0x5b, 0x20, 0xb7, 0x03, 0x54, 0xc0, 0xa4, 0xad, 0x7c, 0xfc, 0x34, 0x0f, 0x94,
	0xde, 0xad, 0xce, 0x6b, 0x57, 0x97, 0xf6, 0xf0, 0xf5, 0x5f, 0x7d, 0x07, 0x00, 0x00, 0xff, 0xff,
	0x05, 0xce, 0x3e, 0xee, 0x0a, 0x04, 0x00, 0x00,
}
