package grpcbasicauth

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc"
)

// UnaryServerInterceptor returns an unary interceptor to enable basic authentication.
func UnaryServerInterceptor(username, password string, opts ...BasicAuthOption) grpc.UnaryServerInterceptor {
	o := createBasicAuthOptions(username, password, opts)
	auth := grpc_auth.UnaryServerInterceptor(o.createAuthFunc())
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if o.shouldAuth(info.FullMethod) {
			return auth(ctx, req, info, handler)
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a stream interceptor to enable basic authentication.
func StreamServerInterceptor(username, password string, opts ...BasicAuthOption) grpc.StreamServerInterceptor {
	o := createBasicAuthOptions(username, password, opts)
	auth := grpc_auth.StreamServerInterceptor(o.createAuthFunc())
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if o.shouldAuth(info.FullMethod) {
			return auth(srv, stream, info, handler)
		}
		return handler(srv, stream)
	}
}

// UnaryClientInterceptor returns an unary interceptor to attach basic username and password to metadata.
func UnaryClientInterceptor(username, password string, opts ...BasicAuthOption) grpc.UnaryClientInterceptor {
	o := createBasicAuthOptions(username, password, opts)
	attachMD := o.createAttachMDFunc()

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(attachMD(ctx), method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor returns a stream interceptor to attach basic username and password to metadata.
func StreamClientInterceptor(username, password string, opts ...BasicAuthOption) grpc.StreamClientInterceptor {
	o := createBasicAuthOptions(username, password, opts)
	attachMD := o.createAttachMDFunc()

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(attachMD(ctx), desc, cc, method, opts...)
	}
}
